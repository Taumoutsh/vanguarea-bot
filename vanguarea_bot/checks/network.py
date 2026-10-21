"""Analyse réseau : connexions TCP, SYN flood, trafic entrant, ports en écoute."""

from __future__ import annotations

import ipaddress
import os
import socket
import struct
import time
from collections import Counter
from dataclasses import dataclass, field

from ..config import Config
from ..state import CRITICAL, WARNING, Alert, State
from ..utils import esc

# On lit les tables réseau du PID 1 : avec `pid: host`, c'est l'espace de noms
# réseau de l'hôte, même si le bot tourne dans un conteneur.
PROC_NET = "/proc/1/net"

TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
    "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
    "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}
VIRTUAL_IFACES = ("lo", "docker", "br-", "veth", "virbr", "cni", "flannel", "cali", "tun", "wg", "tailscale")


@dataclass
class Socket:
    proto: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str
    inode: int


def decode_addr(hex_addr: str) -> tuple[str, int]:
    """Décode une adresse de /proc/net/tcp[6] (« 0100007F:0050 »)."""
    ip_hex, port_hex = hex_addr.split(":")
    port = int(port_hex, 16)
    raw = bytes.fromhex(ip_hex)
    if len(raw) == 4:
        return socket.inet_ntop(socket.AF_INET, raw[::-1]), port
    # IPv6 : quatre mots de 32 bits en ordre hôte (little-endian)
    words = struct.unpack("<4I", raw)
    ip6 = ipaddress.IPv6Address(struct.pack(">4I", *words))
    if ip6.ipv4_mapped:
        return str(ip6.ipv4_mapped), port
    return str(ip6), port


def parse_proc_net(content: str, proto: str) -> list[Socket]:
    sockets = []
    for line in content.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue
        lip, lport = decode_addr(parts[1])
        rip, rport = decode_addr(parts[2])
        state = TCP_STATES.get(parts[3], parts[3]) if proto.startswith("tcp") else (
            "LISTEN" if parts[3] == "07" else "OTHER")
        sockets.append(Socket(proto, lip, lport, rip, rport, state, int(parts[9])))
    return sockets


def read_sockets(protos: tuple[str, ...] = ("tcp", "tcp6")) -> list[Socket]:
    out: list[Socket] = []
    for proto in protos:
        try:
            with open(f"{PROC_NET}/{proto}") as fh:
                out += parse_proc_net(fh.read(), proto)
        except OSError:
            continue
    return out


def is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_global


@dataclass
class ConnStats:
    total: int = 0
    by_state: Counter = field(default_factory=Counter)
    established_by_ip: Counter = field(default_factory=Counter)
    syn_recv_by_ip: Counter = field(default_factory=Counter)


def connection_stats(sockets: list[Socket]) -> ConnStats:
    stats = ConnStats()
    for s in sockets:
        if s.state == "LISTEN":
            continue
        stats.total += 1
        stats.by_state[s.state] += 1
        if is_public(s.remote_ip):
            if s.state == "ESTABLISHED":
                stats.established_by_ip[s.remote_ip] += 1
            elif s.state == "SYN_RECV":
                stats.syn_recv_by_ip[s.remote_ip] += 1
    return stats


def read_iface_counters() -> dict[str, tuple[int, int]]:
    """{interface: (octets reçus, paquets reçus)} pour les interfaces physiques."""
    counters = {}
    try:
        with open(f"{PROC_NET}/dev") as fh:
            lines = fh.read().splitlines()[2:]
    except OSError:
        return counters
    for line in lines:
        name, data = line.split(":", 1)
        name = name.strip()
        if name.startswith(VIRTUAL_IFACES):
            continue
        fields = data.split()
        counters[name] = (int(fields[0]), int(fields[1]))
    return counters


def read_syncookies() -> int | None:
    try:
        with open(f"{PROC_NET}/netstat") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return None
    for header, values in zip(lines[::2], lines[1::2]):
        if header.startswith("TcpExt:"):
            data = dict(zip(header.split()[1:], values.split()[1:]))
            return int(data.get("SyncookiesSent", 0))
    return None


def sample_traffic(seconds: float = 3.0) -> dict[str, tuple[float, float]]:
    """Mesure le débit entrant instantané : {interface: (Mbit/s, paquets/s)}."""
    before = read_iface_counters()
    time.sleep(seconds)
    after = read_iface_counters()
    rates = {}
    for iface, (b1, p1) in after.items():
        if iface in before:
            b0, p0 = before[iface]
            rates[iface] = ((b1 - b0) * 8 / seconds / 1e6, (p1 - p0) / seconds)
    return rates


def listening_ports(sockets: list[Socket]) -> set[tuple[str, str, int]]:
    ports = set()
    for s in sockets:
        # Les sockets UDP clients non connectées utilisent des ports éphémères (>= 32768) : on les ignore.
        if s.proto.startswith("udp") and s.local_port >= 32768:
            continue
        if s.state == "LISTEN" and not ipaddress.ip_address(s.local_ip).is_loopback:
            ports.add((s.proto.rstrip("6"), s.local_ip, s.local_port))
    return ports


def socket_owners(inodes: set[int]) -> dict[int, str]:
    """Associe des inodes de sockets à leurs processus (scan de /proc/*/fd)."""
    owners: dict[int, str] = {}
    if not inodes:
        return owners
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            fds = os.listdir(f"/proc/{pid}/fd")
        except OSError:
            continue
        for fd in fds:
            try:
                target = os.readlink(f"/proc/{pid}/fd/{fd}")
            except OSError:
                continue
            if target.startswith("socket:["):
                inode = int(target[8:-1])
                if inode in inodes and inode not in owners:
                    try:
                        with open(f"/proc/{pid}/comm") as fh:
                            owners[inode] = f"{fh.read().strip()} ({pid})"
                    except OSError:
                        owners[inode] = pid
        if len(owners) == len(inodes):
            break
    return owners


def listening_details() -> list[tuple[str, str, int, str]]:
    sockets = [s for s in read_sockets(("tcp", "tcp6", "udp", "udp6")) if s.state == "LISTEN"]
    owners = socket_owners({s.inode for s in sockets})
    seen = set()
    out = []
    for s in sorted(sockets, key=lambda s: (s.proto, s.local_port)):
        key = (s.proto.rstrip("6"), s.local_ip, s.local_port)
        if key in seen:
            continue
        seen.add(key)
        out.append((*key, owners.get(s.inode, "?")))
    return out


def check(cfg: Config, state: State) -> list[Alert]:
    out: list[Alert] = []
    sockets = read_sockets(("tcp", "tcp6", "udp", "udp6"))
    stats = connection_stats([s for s in sockets if s.proto.startswith("tcp")])

    # --- SYN flood
    syn_recv = stats.by_state["SYN_RECV"]
    cookies = read_syncookies()
    with state.lock:
        net = state.section("network")
        prev_cookies = net.get("syncookies")
        net["syncookies"] = cookies
    cookies_delta = cookies - prev_cookies if cookies is not None and prev_cookies is not None else 0
    if syn_recv >= cfg.syn_recv_threshold or cookies_delta >= cfg.syn_recv_threshold * 10:
        top = ", ".join(f"{esc(ip)} ({n})" for ip, n in stats.syn_recv_by_ip.most_common(5))
        out.append(Alert("net:synflood", CRITICAL, "Possible attaque SYN flood (DDoS)",
                         f"{syn_recv} connexions semi-ouvertes (SYN_RECV), "
                         f"{max(cookies_delta, 0)} SYN cookies envoyés depuis la dernière vérification.\n"
                         f"Sources principales : {top or 'adresses usurpées / variées'}"))

    # --- Trop de connexions depuis une même IP
    for ip, count in stats.established_by_ip.most_common(5):
        if count >= cfg.conn_per_ip_threshold:
            out.append(Alert(f"net:connflood:{ip}", WARNING, f"{count} connexions simultanées depuis {esc(ip)}",
                             "Possible flood applicatif ou client abusif.\n"
                             f"💡 <code>ufw deny from {esc(ip)}</code>"))

    # --- Débit entrant anormal (DDoS volumétrique)
    for iface, (mbps, pps) in sample_traffic().items():
        if mbps >= cfg.rx_mbps_threshold or pps >= cfg.rx_pps_threshold:
            out.append(Alert(f"net:traffic:{iface}", CRITICAL, f"Trafic entrant anormal sur {esc(iface)}",
                             f"{mbps:.0f} Mbit/s — {pps:,.0f} paquets/s".replace(",", " ")))

    # --- Nouveaux ports en écoute
    current = listening_ports(sockets)
    with state.lock:
        known_raw = net.get("listening")
        net["listening"] = sorted([list(p) for p in current])
    if known_raw is not None:
        known = {tuple(p) for p in known_raw}
        new_ports = current - known
        if new_ports:
            owners = socket_owners({s.inode for s in sockets if (s.proto.rstrip("6"), s.local_ip, s.local_port) in new_ports})
            by_port = {}
            for s in sockets:
                key = (s.proto.rstrip("6"), s.local_ip, s.local_port)
                if key in new_ports:
                    by_port[key] = owners.get(s.inode, "?")
            body = "\n".join(f"• {p}/{port} sur {esc(ip)} — {esc(by_port.get((p, ip, port), '?'))}"
                             for p, ip, port in sorted(new_ports))
            out.append(Alert("net:newports:" + ",".join(f"{p}/{port}" for p, _, port in sorted(new_ports)),
                             WARNING, "Nouveau(x) port(s) en écoute", body, stateful=False))
    return out


def format_network(cfg: Config) -> str:
    sockets = read_sockets()
    stats = connection_stats(sockets)
    traffic = sample_traffic(2.0)
    lines = ["🌐 <b>Réseau</b>", ""]
    for iface, (mbps, pps) in traffic.items():
        lines.append(f"📶 {esc(iface)} : {mbps:.1f} Mbit/s entrant, {pps:.0f} paquets/s")
    states = ", ".join(f"{k} {v}" for k, v in stats.by_state.most_common())
    lines.append(f"🔗 Connexions TCP : {stats.total} ({esc(states)})")
    syn = stats.by_state["SYN_RECV"]
    lines.append(f"{'🔴' if syn >= cfg.syn_recv_threshold else '🟢'} SYN_RECV : {syn}")
    if stats.established_by_ip:
        lines.append("")
        lines.append("<b>Top IP publiques connectées</b>")
        for ip, n in stats.established_by_ip.most_common(8):
            lines.append(f"• <code>{esc(ip)}</code> : {n}")
    return "\n".join(lines)


def format_ports() -> str:
    lines = ["🚪 <b>Ports en écoute</b>", ""]
    for proto, ip, port, owner in listening_details():
        exposure = "🔒" if ipaddress.ip_address(ip).is_loopback else "🌍"
        lines.append(f"{exposure} {proto}/{port} sur <code>{esc(ip)}</code> — {esc(owner)}")
    lines.append("\n🌍 = accessible depuis l'extérieur (sauf pare-feu), 🔒 = local uniquement")
    return "\n".join(lines)
