"""Analyse des journaux d'authentification SSH / sudo."""

from __future__ import annotations

import base64
import hashlib
import re
import time
from collections import Counter
from dataclasses import dataclass, field

from ..config import Config
from ..logtail import read_new_lines
from ..state import CRITICAL, INFO, WARNING, Alert, State
from ..utils import esc, human_duration, run_host_cmd
from . import geoip

IP = r"(?P<ip>[0-9a-fA-F:.]+)"
FAIL_PATTERNS = [
    re.compile(rf"Failed (?:password|publickey|none) for (?:invalid user )?(?P<user>\S*) from {IP}"),
    re.compile(rf"Invalid user (?P<user>\S*) from {IP}"),
    re.compile(rf"maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S*) from {IP}"),
    re.compile(rf"Connection closed by authenticating user (?P<user>\S+) {IP} port \d+ \[preauth\]"),
]
ACCEPT = re.compile(rf"Accepted (?P<method>\S+) for (?P<user>\S+) from {IP} port \d+"
                    r"(?: ssh2(?:: (?P<key_type>\S+) (?P<fingerprint>SHA256:\S+))?)?")
KEY_LINE = re.compile(r"(?:^|\s)(?P<type>(?:sk-)?(?:ssh|ecdsa)-[\w@.-]+)\s+(?P<blob>[A-Za-z0-9+/]+=*)(?:\s+(?P<comment>.*))?$")
MAX_HISTORY = 500
SUDO_FAIL = re.compile(r"sudo(?:\[\d+\])?:\s+(?P<user>\S+) : (?:\d+ incorrect password attempts?|.*authentication failure)")
ROOT_ACCEPT_WARNING = {"root"}

AUTH_LOGS = ["/var/log/auth.log", "/var/log/secure"]


@dataclass
class Login:
    user: str
    ip: str
    method: str  # publickey, password, keyboard-interactive/pam...
    key_type: str | None = None
    fingerprint: str | None = None  # « SHA256:... » pour une connexion par clé


@dataclass
class SshEvents:
    failures: Counter = field(default_factory=Counter)  # ip -> nombre d'échecs
    users_tried: Counter = field(default_factory=Counter)
    logins: list[Login] = field(default_factory=list)
    sudo_failures: Counter = field(default_factory=Counter)


def parse_lines(lines: list[str]) -> SshEvents:
    ev = SshEvents()
    for line in lines:
        if "sshd" in line:
            m = ACCEPT.search(line)
            if m:
                ev.logins.append(Login(m["user"], m["ip"], m["method"], m["key_type"], m["fingerprint"]))
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


def fingerprint(blob: str) -> str | None:
    """Empreinte SHA256 d'une clé publique, au format d'OpenSSH (« SHA256:... »)."""
    try:
        digest = hashlib.sha256(base64.b64decode(blob)).digest()
    except ValueError:
        return None
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def parse_authorized_keys(content: str) -> dict[str, tuple[str, str]]:
    """{empreinte: (type, commentaire)} pour un fichier authorized_keys (options éventuelles ignorées)."""
    keys = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = KEY_LINE.search(line)
        if m and (fp := fingerprint(m["blob"])):
            keys[fp] = (m["type"], (m["comment"] or "").strip())
    return keys


def _home(cfg: Config, user: str) -> str | None:
    try:
        for line in cfg.host_path("/etc/passwd").read_text(errors="replace").splitlines():
            parts = line.split(":")
            if len(parts) > 5 and parts[0] == user:
                return parts[5]
    except OSError:
        pass
    return None


def authorized_keys(cfg: Config, user: str) -> dict[str, tuple[str, str]]:
    home = _home(cfg, user)
    keys: dict[str, tuple[str, str]] = {}
    for name in ("authorized_keys", "authorized_keys2"):
        try:
            keys.update(parse_authorized_keys(cfg.host_path(f"{home}/.ssh/{name}").read_text(errors="replace")))
        except (OSError, TypeError):
            continue
    return keys


def login_alert(cfg: Config, state: State, login: Login, now: float | None = None) -> Alert | None:
    """Alerte enrichie : clé utilisée, pays / opérateur, IP ou pays jamais vus."""
    now = time.time() if now is None else now
    geo = geoip.lookup(cfg, state, login.ip)
    country = geo.get("country")
    with state.lock:
        history = state.section("ssh_history")  # ip -> {first, last, count, country}
        known_countries = {h.get("country") for h in history.values() if h.get("country")}
        previous = dict(history.get(login.ip) or {})
        first_ever = not history
        history[login.ip] = {"first": previous.get("first", now), "last": now,
                             "count": previous.get("count", 0) + 1, "country": country or previous.get("country")}
        if len(history) > MAX_HISTORY:
            for ip in sorted(history, key=lambda k: history[k]["last"])[: len(history) - MAX_HISTORY]:
                del history[ip]
    if login.ip in cfg.ssh_trusted_ips:
        return None

    level, title, notes = INFO, "Connexion SSH réussie", []
    if login.fingerprint:
        key = authorized_keys(cfg, login.user).get(login.fingerprint)
        if key:
            who = f"avec la clé 🔑 <b>{esc(key[1] or 'sans commentaire')}</b> ({esc(login.key_type or key[0])})"
        else:
            level = WARNING
            who = f"avec une <b>clé inconnue</b> 🔑 <code>{esc(login.fingerprint)}</code>"
            notes.append("⚠️ Clé absente des authorized_keys de ce compte : vérifiez qu'elle est bien à vous.")
    elif login.method == "password" or "keyboard-interactive" in login.method:
        level = WARNING
        who = "par <b>mot de passe</b> 🔓"
        notes.append("💡 Préférez une clé SSH et désactivez PasswordAuthentication.")
    else:
        who = f"({esc(login.method)})"
    if login.user in ROOT_ACCEPT_WARNING:
        level = WARNING
        notes.append("⚠️ Connexion directe en root : préférez un utilisateur + sudo.")

    if not first_ever and country and country not in known_countries:
        level, title = CRITICAL, "Connexion SSH depuis un pays jamais vu"
        notes.insert(0, "🚨 Si ce n'est pas vous : changez immédiatement les clés et vérifiez le serveur.")
    elif previous:
        notes.insert(0, f"✅ IP connue (dernière connexion il y a {human_duration(now - previous['last'])}, "
                        f"{previous.get('count', 0) + 1} au total)")
    elif not first_ever:
        notes.insert(0, "🆕 Première connexion depuis cette IP")

    body = [f"👤 <b>{esc(login.user)}</b> {who}", f"🌍 {geoip.describe(login.ip, geo)}", *notes]
    return Alert(f"ssh:login:{login.user}:{login.ip}", level, title, "\n".join(body), stateful=False)


def check(cfg: Config, state: State) -> list[Alert]:
    with state.lock:
        lines = read_auth_lines(cfg, state)
    ev = parse_lines(lines)
    out: list[Alert] = []

    for ip, count in ev.failures.items():
        state.incr("ssh_failed", ip, count)
        if count >= cfg.ssh_fail_threshold and ip not in cfg.ssh_trusted_ips:
            origin = geoip.describe(ip, geoip.lookup(cfg, state, ip))
            out.append(Alert(f"ssh:bruteforce:{ip}", WARNING, f"Brute force SSH depuis {esc(ip)}",
                             f"🌍 {origin}\n"
                             f"{count} échecs d'authentification sur la dernière période.\n"
                             f"Comptes visés : {esc(', '.join(u for u, _ in ev.users_tried.most_common(5)))}\n"
                             f"💡 <code>fail2ban</code> ou <code>ufw deny from {esc(ip)}</code>",
                             stateful=False))
    total = sum(ev.failures.values())
    if total >= cfg.ssh_fail_threshold * 5 and len(ev.failures) >= 10:
        out.append(Alert("ssh:distributed", CRITICAL, "Brute force SSH distribué",
                         f"{total} échecs depuis {len(ev.failures)} IP différentes.", stateful=False))

    for login in ev.logins:
        state.incr("ssh_logins", f"{login.user}@{login.ip}")
        alert = login_alert(cfg, state, login)
        if alert:
            out.append(alert)

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
