"""Analyse des journaux d'authentification SSH / sudo."""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

from ..config import Config
from ..logtail import read_new_lines
from ..state import CRITICAL, INFO, WARNING, Alert, State
from ..utils import esc, run_host_cmd

IP = r"(?P<ip>[0-9a-fA-F:.]+)"
FAIL_PATTERNS = [
    re.compile(rf"Failed (?:password|publickey|none) for (?:invalid user )?(?P<user>\S*) from {IP}"),
    re.compile(rf"Invalid user (?P<user>\S*) from {IP}"),
    re.compile(rf"maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S*) from {IP}"),
    re.compile(rf"Connection closed by authenticating user (?P<user>\S+) {IP} port \d+ \[preauth\]"),
]
ACCEPT = re.compile(rf"Accepted (?P<method>\S+) for (?P<user>\S+) from {IP} port \d+")
SUDO_FAIL = re.compile(r"sudo(?:\[\d+\])?:\s+(?P<user>\S+) : (?:\d+ incorrect password attempts?|.*authentication failure)")
ROOT_ACCEPT_WARNING = {"root"}

AUTH_LOGS = ["/var/log/auth.log", "/var/log/secure"]


@dataclass
class SshEvents:
    failures: Counter = field(default_factory=Counter)  # ip -> nombre d'échecs
    users_tried: Counter = field(default_factory=Counter)
    logins: list[tuple[str, str, str]] = field(default_factory=list)  # (user, ip, méthode)
    sudo_failures: Counter = field(default_factory=Counter)


def parse_lines(lines: list[str]) -> SshEvents:
    ev = SshEvents()
    for line in lines:
        if "sshd" in line:
            m = ACCEPT.search(line)
            if m:
                ev.logins.append((m["user"], m["ip"], m["method"]))
                continue
            for pattern in FAIL_PATTERNS:
                m = pattern.search(line)
                if m:
                    ev.failures[m["ip"]] += 1
                    ev.users_tried[m["user"] or "?"] += 1
                    break
        elif "sudo" in line:
            m = SUDO_FAIL.search(line)
            if m:
                ev.sudo_failures[m["user"]] += 1
    return ev


def read_auth_lines(cfg: Config, state: State) -> list[str]:
    """Nouvelles lignes d'authentification (fichier auth.log ou journald)."""
    positions = state.section("log_positions")
    for log_path in AUTH_LOGS:
        path = cfg.host_path(log_path)
        if path.exists():
            return read_new_lines(path, positions)

    # Pas de fichier auth.log (Debian 12+, Ubuntu minimal...) : on interroge journald.
    journal = state.section("journal")
    args = ["journalctl", "--no-pager", "-o", "short-iso", "--show-cursor",
            "-u", "ssh.service", "-u", "sshd.service", "-u", "ssh@*.service", "-t", "sudo"]
    cursor = journal.get("auth_cursor")
    args += ["--after-cursor", cursor] if cursor else ["--since", "-2min"]
    res = run_host_cmd(cfg, args, timeout=60)
    if not res.ok:
        return []
    lines = []
    for line in res.stdout.splitlines():
        if line.startswith("-- cursor: "):
            journal["auth_cursor"] = line[len("-- cursor: "):]
        else:
            lines.append(line)
    return lines


def check(cfg: Config, state: State) -> list[Alert]:
    with state.lock:
        lines = read_auth_lines(cfg, state)
    ev = parse_lines(lines)
    out: list[Alert] = []

    for ip, count in ev.failures.items():
        state.incr("ssh_failed", ip, count)
        if count >= cfg.ssh_fail_threshold and ip not in cfg.ssh_trusted_ips:
            out.append(Alert(f"ssh:bruteforce:{ip}", WARNING, f"Brute force SSH depuis {esc(ip)}",
                             f"{count} échecs d'authentification sur la dernière période.\n"
                             f"Comptes visés : {esc(', '.join(u for u, _ in ev.users_tried.most_common(5)))}\n"
                             f"💡 <code>fail2ban</code> ou <code>ufw deny from {esc(ip)}</code>",
                             stateful=False))
    total = sum(ev.failures.values())
    if total >= cfg.ssh_fail_threshold * 5 and len(ev.failures) >= 10:
        out.append(Alert("ssh:distributed", CRITICAL, "Brute force SSH distribué",
                         f"{total} échecs depuis {len(ev.failures)} IP différentes.", stateful=False))

    for user, ip, method in ev.logins:
        state.incr("ssh_logins", f"{user}@{ip}")
        if ip in cfg.ssh_trusted_ips:
            continue
        level = WARNING if user in ROOT_ACCEPT_WARNING or method == "password" else INFO
        out.append(Alert(f"ssh:login:{user}:{ip}", level, "Connexion SSH réussie",
                         f"Utilisateur <b>{esc(user)}</b> depuis <code>{esc(ip)}</code> ({esc(method)})",
                         stateful=False))

    for user, count in ev.sudo_failures.items():
        out.append(Alert(f"sudo:fail:{user}", WARNING, f"Échec(s) sudo pour {esc(user)}",
                         f"{count} tentative(s) de mot de passe incorrect.", stateful=False))
    return out


def fail2ban_status(cfg: Config) -> dict[str, tuple[int, int]] | None:
    """{jail: (bannis actuellement, total bannis)} ou None si fail2ban est absent."""
    res = run_host_cmd(cfg, ["fail2ban-client", "status"], timeout=20)
    if not res.ok:
        return None
    jails: list[str] = []
    for line in res.stdout.splitlines():
        if "Jail list:" in line:
            jails = [j.strip() for j in line.split(":", 1)[1].split(",") if j.strip()]
    status = {}
    for jail in jails:
        r = run_host_cmd(cfg, ["fail2ban-client", "status", jail], timeout=20)
        current = total = 0
        for line in r.stdout.splitlines():
            if "Currently banned:" in line:
                current = int(line.rsplit(":", 1)[1])
            elif "Total banned:" in line:
                total = int(line.rsplit(":", 1)[1])
        status[jail] = (current, total)
    return status
