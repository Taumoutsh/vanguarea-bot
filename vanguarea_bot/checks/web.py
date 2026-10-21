"""Analyse des logs d'accès HTTP (nginx, Apache, Traefik, Caddy...) : flood et scans."""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from urllib.parse import unquote

from ..config import Config
from ..logtail import read_new_lines
from ..state import WARNING, Alert, State
from ..utils import esc

# Format « combined » / « common » : IP - - [date] "GET /path HTTP/1.1" 404 ...
COMBINED = re.compile(r'^(?P<ip>\S+) \S+ \S+ \[[^\]]+\] "(?:\S+ )?(?P<path>[^" ]*)[^"]*" (?P<status>\d{3})')

SUSPICIOUS = re.compile(
    r"(\.\./|/\.env|/\.git/|/\.aws|/\.ssh|wp-login\.php|xmlrpc\.php|/wp-admin|phpmyadmin|/pma/|"
    r"/etc/passwd|/proc/self|union(\s|\+)+select|<script|\$\{jndi:|/cgi-bin/|/boaform|/HNAP1|"
    r"/actuator|/vendor/phpunit|eval-stdin|/shell|cmd=|/\.well-known/.*\.php|\.(?:bak|sql|old)$)",
    re.IGNORECASE,
)


@dataclass
class Request:
    ip: str
    path: str
    status: int


@dataclass
class WebEvents:
    requests: Counter = field(default_factory=Counter)  # ip -> requêtes
    errors: Counter = field(default_factory=Counter)  # ip -> réponses 4xx
    suspicious: Counter = field(default_factory=Counter)  # ip -> requêtes suspectes
    samples: dict = field(default_factory=lambda: defaultdict(list))  # ip -> chemins suspects


def parse_line(line: str) -> Request | None:
    line = line.strip()
    if not line:
        return None
    if line.startswith("{"):
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None
        # Traefik (ClientHost/RequestPath/DownstreamStatus), Caddy (request.remote_ip/uri) ou générique
        req = data.get("request") if isinstance(data.get("request"), dict) else {}
        ip = data.get("ClientHost") or req.get("client_ip") or req.get("remote_ip") or data.get("remote_addr")
        path = data.get("RequestPath") or req.get("uri") or data.get("request_uri") or data.get("path") or ""
        status = data.get("DownstreamStatus") or data.get("status") or 0
        if not ip:
            return None
        return Request(str(ip), str(path), int(status))
    m = COMBINED.match(line)
    if not m:
        return None
    return Request(m["ip"], m["path"], int(m["status"]))


def analyse(lines: list[str]) -> WebEvents:
    ev = WebEvents()
    for line in lines:
        req = parse_line(line)
        if req is None:
            continue
        ev.requests[req.ip] += 1
        if 400 <= req.status < 500:
            ev.errors[req.ip] += 1
        if SUSPICIOUS.search(unquote(req.path)):
            ev.suspicious[req.ip] += 1
            if len(ev.samples[req.ip]) < 3:
                ev.samples[req.ip].append(req.path[:80])
    return ev


def check(cfg: Config, state: State) -> list[Alert]:
    if not cfg.access_logs:
        return []
    lines: list[str] = []
    with state.lock:
        positions = state.section("log_positions")
        for log_path in cfg.access_logs:
            lines += read_new_lines(cfg.host_path(log_path), positions)
    ev = analyse(lines)
    out: list[Alert] = []
    for ip, count in ev.suspicious.items():
        state.incr("http_suspicious", ip, count)
    for ip, count in ev.requests.most_common(10):
        if count >= cfg.http_rate_threshold:
            out.append(Alert(f"web:flood:{ip}", WARNING, f"Flood HTTP depuis {esc(ip)}",
                             f"{count} requêtes depuis la dernière vérification.", stateful=False))
    for ip in set(ev.suspicious) | set(ev.errors):
        score = ev.suspicious[ip] + ev.errors[ip] // 2
        if score >= cfg.http_scan_threshold:
            samples = "\n".join(f"• <code>{esc(p)}</code>" for p in ev.samples.get(ip, []))
            out.append(Alert(f"web:scan:{ip}", WARNING, f"Scan de vulnérabilités web depuis {esc(ip)}",
                             f"{ev.suspicious[ip]} requête(s) suspecte(s), {ev.errors[ip]} erreur(s) 4xx.\n{samples}",
                             stateful=False))
    return out
