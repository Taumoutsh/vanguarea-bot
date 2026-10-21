"""Surveillance de l'intégrité de fichiers sensibles (comptes, sudo, clés SSH, cron...)."""

from __future__ import annotations

import glob
import hashlib
from pathlib import Path

from ..config import Config
from ..state import CRITICAL, WARNING, Alert, State
from ..utils import esc

CRITICAL_FILES = {"/etc/ld.so.preload", "/etc/sudoers", "/root/.ssh/authorized_keys"}


def _hash_file(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _expand(cfg: Config, pattern: str) -> list[str]:
    """Résout les jokers et les répertoires ; retourne des chemins vus depuis l'hôte."""
    root = str(cfg.host_root).rstrip("/")
    matches = glob.glob(str(cfg.host_path(pattern))) if any(c in pattern for c in "*?[") else [str(cfg.host_path(pattern))]
    files = []
    for match in matches:
        p = Path(match)
        if p.is_dir():
            files += [str(f) for f in sorted(p.iterdir()) if f.is_file()]
        elif p.exists():
            files.append(match)
    return [f[len(root):] if root and f.startswith(root) else f for f in files]


def snapshot(cfg: Config) -> dict[str, str]:
    result = {}
    for pattern in cfg.watched_files:
        for host_file in _expand(cfg, pattern):
            digest = _hash_file(cfg.host_path(host_file))
            if digest:
                result[host_file] = digest
    return result


def _users(cfg: Config) -> set[str]:
    try:
        return {line.split(":")[0] for line in cfg.host_path("/etc/passwd").read_text().splitlines() if line}
    except OSError:
        return set()


def _key_count(cfg: Config, host_file: str) -> int:
    try:
        lines = cfg.host_path(host_file).read_text(errors="replace").splitlines()
    except OSError:
        return 0
    return sum(1 for l in lines if l.strip() and not l.lstrip().startswith("#"))


def check(cfg: Config, state: State) -> list[Alert]:
    current = snapshot(cfg)
    with state.lock:
        integ = state.section("integrity")
        previous: dict[str, str] | None = integ.get("hashes")
        prev_users = set(integ.get("users", []))
        users = _users(cfg)
        prev_keys = integ.get("key_counts", {})
        key_counts = {f: _key_count(cfg, f) for f in current if f.endswith("authorized_keys")}
        integ.update(hashes=current, users=sorted(users), key_counts=key_counts)
    if previous is None:
        return []  # première exécution : on établit la référence

    out: list[Alert] = []
    changed = sorted(f for f in current if f in previous and current[f] != previous[f])
    added = sorted(f for f in current if f not in previous)
    removed = sorted(f for f in previous if f not in current)
    if not (changed or added or removed):
        return out

    details = []
    for f in changed:
        line = f"✏️ modifié : <code>{esc(f)}</code>"
        if f.endswith("authorized_keys"):
            line += f" ({prev_keys.get(f, '?')} → {key_counts.get(f, '?')} clé(s))"
        details.append(line)
    details += [f"➕ ajouté : <code>{esc(f)}</code>" for f in added]
    details += [f"➖ supprimé : <code>{esc(f)}</code>" for f in removed]
    new_users = users - prev_users
    gone_users = prev_users - users
    if new_users:
        details.append(f"👤 nouveau(x) compte(s) : <b>{esc(', '.join(sorted(new_users)))}</b>")
    if gone_users:
        details.append(f"👤 compte(s) supprimé(s) : {esc(', '.join(sorted(gone_users)))}")

    touched = set(changed) | set(added)
    level = CRITICAL if touched & CRITICAL_FILES or any(f.endswith("authorized_keys") for f in added) else WARNING
    digest = hashlib.sha1("".join(sorted(current.values())).encode()).hexdigest()[:12]
    out.append(Alert(f"integrity:{digest}", level, "Fichiers sensibles modifiés",
                     "\n".join(details) + "\n\nSi ce n'est pas vous, vérifiez immédiatement le serveur.",
                     stateful=False))
    return out
