"""État de l'OS : ressources, mises à jour, services en échec, redémarrage requis."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field

import psutil

from ..config import Config
from ..state import CRITICAL, WARNING, Alert
from ..utils import bar, esc, human_bytes, human_duration, level_icon, run_host_cmd

REAL_FILESYSTEMS = {"ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "jfs", "reiserfs"}


@dataclass
class Disk:
    mountpoint: str
    device: str
    total: int
    used: int
    percent: float
    inode_percent: float


@dataclass
class SystemStatus:
    hostname: str
    os_name: str
    kernel: str
    uptime: float
    cpu_count: int
    cpu_percent: float
    load: tuple[float, float, float]
    mem_total: int
    mem_used: int
    mem_percent: float
    swap_total: int
    swap_percent: float
    disks: list[Disk] = field(default_factory=list)
    updates: list[str] | None = None
    security_updates: list[str] = field(default_factory=list)
    reboot_required: bool = False
    reboot_packages: list[str] = field(default_factory=list)
    failed_units: list[str] | None = None
    top_processes: list[tuple[str, float, int]] = field(default_factory=list)
    zombies: int = 0
    extra_uid0: list[str] = field(default_factory=list)


def _read(cfg: Config, path: str) -> str:
    try:
        return cfg.host_path(path).read_text(errors="replace")
    except OSError:
        return ""


def os_name(cfg: Config) -> str:
    for line in _read(cfg, "/etc/os-release").splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"')
    return "inconnu"


def list_disks(cfg: Config) -> list[Disk]:
    """Liste les partitions de l'hôte (via les montages du PID 1)."""
    mounts = ""
    for path in ("/proc/1/mounts", "/proc/mounts"):
        try:
            mounts = open(path).read()
            break
        except OSError:
            continue
    disks: list[Disk] = []
    seen: set[str] = set()
    for line in mounts.splitlines():
        parts = line.split()
        if len(parts) < 3 or parts[2] not in REAL_FILESYSTEMS:
            continue
        device, mountpoint = parts[0], parts[1].replace("\\040", " ")
        if device in seen or mountpoint.startswith(("/var/lib/docker", "/snap", "/run")):
            continue
        seen.add(device)
        target = cfg.host_path(mountpoint)
        try:
            st = os.statvfs(target)
        except OSError:
            continue
        total = st.f_blocks * st.f_frsize
        if total == 0:
            continue
        used = (st.f_blocks - st.f_bfree) * st.f_frsize
        avail = st.f_bavail * st.f_frsize
        percent = used / (used + avail) * 100 if used + avail else 0
        inode_percent = (st.f_files - st.f_ffree) / st.f_files * 100 if st.f_files else 0
        disks.append(Disk(mountpoint, device, total, used, round(percent, 1), round(inode_percent, 1)))
    return disks


def pending_updates(cfg: Config) -> tuple[list[str] | None, list[str]]:
    """Paquets à mettre à jour (apt ou dnf). Retourne (tous, sécurité)."""
    # Cache en mémoire : fonctionne même si le système de fichiers de l'hôte est monté en lecture seule.
    res = run_host_cmd(cfg, ["apt-get", "-s", "-o", "Debug::NoLocking=1", "-o", "Dir::Cache::pkgcache=",
                             "-o", "Dir::Cache::srcpkgcache=", "dist-upgrade"], timeout=120)
    if res.returncode != 127:
        if not res.ok:
            return None, []
        updates, security = [], []
        for line in res.stdout.splitlines():
            if line.startswith("Inst "):
                pkg = line.split()[1]
                updates.append(pkg)
                if "security" in line.lower():
                    security.append(pkg)
        return updates, security

    res = run_host_cmd(cfg, ["dnf", "-q", "check-update"], timeout=180)
    if res.returncode in (0, 100):
        updates = [l.split()[0] for l in res.stdout.splitlines() if l and not l.startswith(" ")]
        sec = run_host_cmd(cfg, ["dnf", "-q", "updateinfo", "list", "--security"], timeout=180)
        security = [l.split()[-1] for l in sec.stdout.splitlines() if l.strip()] if sec.ok else []
        return updates, security
    return None, []


def failed_units(cfg: Config) -> list[str] | None:
    res = run_host_cmd(cfg, ["systemctl", "--failed", "--no-legend", "--plain"], timeout=30)
    if not res.ok:
        return None
    return [line.split()[0] for line in res.stdout.splitlines() if line.strip()]


def uid0_accounts(cfg: Config) -> list[str]:
    users = []
    for line in _read(cfg, "/etc/passwd").splitlines():
        parts = line.split(":")
        if len(parts) > 3 and parts[2] == "0" and parts[0] != "root":
            users.append(parts[0])
    return users


def collect(cfg: Config, with_updates: bool = True) -> SystemStatus:
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    procs = []
    zombies = 0
    for p in psutil.process_iter(["name", "memory_percent", "memory_info", "status"]):
        info = p.info
        if info.get("status") == psutil.STATUS_ZOMBIE:
            zombies += 1
        if info.get("memory_info"):
            procs.append((info["name"] or "?", info["memory_percent"] or 0.0, info["memory_info"].rss))
    procs.sort(key=lambda p: p[1], reverse=True)

    status = SystemStatus(
        hostname=cfg.server_name or _read(cfg, "/etc/hostname").strip() or os.uname().nodename,
        os_name=os_name(cfg),
        kernel=os.uname().release,
        uptime=time.time() - psutil.boot_time(),
        cpu_count=psutil.cpu_count() or 1,
        cpu_percent=psutil.cpu_percent(interval=1),
        load=os.getloadavg(),
        mem_total=mem.total,
        mem_used=mem.total - mem.available,
        mem_percent=mem.percent,
        swap_total=swap.total,
        swap_percent=swap.percent,
        disks=list_disks(cfg),
        failed_units=failed_units(cfg),
        top_processes=procs[:5],
        zombies=zombies,
        extra_uid0=uid0_accounts(cfg),
    )
    status.reboot_required = cfg.host_path("/run/reboot-required").exists()
    if status.reboot_required:
        status.reboot_packages = _read(cfg, "/run/reboot-required.pkgs").split()
    if with_updates:
        status.updates, status.security_updates = pending_updates(cfg)
    return status


def alerts(status: SystemStatus, cfg: Config) -> list[Alert]:
    out: list[Alert] = []
    if status.cpu_percent >= cfg.cpu_threshold:
        out.append(Alert("sys:cpu", WARNING, f"CPU élevé : {status.cpu_percent:.0f}%",
                         _top_processes(status)))
    if status.mem_percent >= cfg.mem_threshold:
        out.append(Alert("sys:mem", CRITICAL if status.mem_percent >= 97 else WARNING,
                         f"Mémoire élevée : {status.mem_percent:.0f}%", _top_processes(status)))
    if status.swap_total and status.swap_percent >= cfg.swap_threshold:
        out.append(Alert("sys:swap", WARNING, f"Swap élevé : {status.swap_percent:.0f}%"))
    load_ratio = status.load[1] / status.cpu_count
    if load_ratio >= cfg.load_threshold:
        out.append(Alert("sys:load", WARNING,
                         f"Charge système élevée : {status.load[1]:.2f} ({status.cpu_count} CPU)"))
    for d in status.disks:
        if d.percent >= cfg.disk_threshold:
            out.append(Alert(f"sys:disk:{d.mountpoint}", CRITICAL if d.percent >= 95 else WARNING,
                             f"Disque {d.mountpoint} rempli à {d.percent:.0f}%",
                             f"{human_bytes(d.used)} / {human_bytes(d.total)} ({esc(d.device)})"))
        if d.inode_percent >= cfg.inode_threshold:
            out.append(Alert(f"sys:inode:{d.mountpoint}", WARNING,
                             f"Inodes {d.mountpoint} utilisés à {d.inode_percent:.0f}%"))
    if status.failed_units:
        out.append(Alert("sys:failed_units:" + ",".join(sorted(status.failed_units)), WARNING,
                         f"{len(status.failed_units)} service(s) systemd en échec",
                         "\n".join(f"• <code>{esc(u)}</code>" for u in status.failed_units)))
    if status.reboot_required:
        out.append(Alert("sys:reboot", WARNING, "Redémarrage du serveur requis",
                         "Paquets : " + esc(", ".join(status.reboot_packages[:10]) or "?")))
    if status.security_updates:
        out.append(Alert("sys:security_updates", WARNING,
                         f"{len(status.security_updates)} mise(s) à jour de sécurité disponible(s)",
                         esc(", ".join(status.security_updates[:20]))))
    if status.extra_uid0:
        out.append(Alert("sys:uid0", CRITICAL, "Compte(s) avec UID 0 autre(s) que root !",
                         esc(", ".join(status.extra_uid0))))
    return out


def _top_processes(status: SystemStatus) -> str:
    return "Top mémoire : " + ", ".join(
        f"{esc(name)} ({pct:.0f}%)" for name, pct, _ in status.top_processes[:3]
    )


def format_status(status: SystemStatus, cfg: Config) -> str:
    lines = [
        f"🖥 <b>{esc(status.hostname)}</b>",
        f"<i>{esc(status.os_name)} — noyau {esc(status.kernel)}</i>",
        f"⏱ Uptime : {human_duration(status.uptime)}",
        "",
        f"{level_icon(status.cpu_percent, cfg.cpu_threshold)} CPU : {bar(status.cpu_percent)} "
        f"{status.cpu_percent:.0f}% ({status.cpu_count} cœurs)",
        f"   Charge : {status.load[0]:.2f} / {status.load[1]:.2f} / {status.load[2]:.2f}",
        f"{level_icon(status.mem_percent, cfg.mem_threshold)} RAM : {bar(status.mem_percent)} "
        f"{status.mem_percent:.0f}% ({human_bytes(status.mem_used)} / {human_bytes(status.mem_total)})",
    ]
    if status.swap_total:
        lines.append(f"{level_icon(status.swap_percent, cfg.swap_threshold)} Swap : "
                     f"{bar(status.swap_percent)} {status.swap_percent:.0f}%")
    lines.append("")
    lines.append("💾 <b>Disques</b>")
    for d in status.disks:
        lines.append(f"{level_icon(d.percent, cfg.disk_threshold)} <code>{esc(d.mountpoint)}</code> "
                     f"{bar(d.percent)} {d.percent:.0f}% ({human_bytes(d.used)} / {human_bytes(d.total)})")
    lines.append("")
    if status.updates is None:
        lines.append("📦 Mises à jour : non vérifiables")
    elif status.updates:
        lines.append(f"📦 Mises à jour : {len(status.updates)} dont "
                     f"<b>{len(status.security_updates)} de sécurité</b>")
    else:
        lines.append("📦 Système à jour ✅")
    if status.reboot_required:
        lines.append("🔁 <b>Redémarrage requis</b>")
    if status.failed_units is None:
        lines.append("⚙️ Services systemd : non vérifiables")
    elif status.failed_units:
        lines.append(f"⚙️ Services en échec : {esc(', '.join(status.failed_units))}")
    else:
        lines.append("⚙️ Aucun service systemd en échec ✅")
    if status.zombies:
        lines.append(f"🧟 Processus zombies : {status.zombies}")
    if status.extra_uid0:
        lines.append(f"🚨 Comptes UID 0 suspects : {esc(', '.join(status.extra_uid0))}")
    return "\n".join(lines)
