"""Fonctions utilitaires partagées."""

from __future__ import annotations

import html
import logging
import shutil
import subprocess
from dataclasses import dataclass

from .config import Config

log = logging.getLogger(__name__)

TELEGRAM_MAX_LEN = 4000


@dataclass
class CmdResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def run_host_cmd(cfg: Config, args: list[str], timeout: int = 60) -> CmdResult:
    """Exécute une commande de l'hôte.

    En mode conteneur (HOST_ROOT != /), la commande est lancée via ``chroot``
    dans le système de fichiers de l'hôte pour utiliser ses propres binaires
    (apt, systemctl, journalctl, fail2ban-client...).
    """
    if cfg.containerized:
        args = ["chroot", str(cfg.host_root), *args]
    elif shutil.which(args[0]) is None:
        return CmdResult(127, "", f"{args[0]}: introuvable")
    return run_cmd(args, timeout=timeout)


def run_cmd(args: list[str], timeout: int = 60) -> CmdResult:
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError:
        return CmdResult(127, "", f"{args[0]}: introuvable")
    except subprocess.TimeoutExpired:
        return CmdResult(124, "", f"{' '.join(args)}: délai dépassé ({timeout}s)")
    return CmdResult(proc.returncode, proc.stdout, proc.stderr)


def esc(value: object) -> str:
    return html.escape(str(value), quote=False)


def human_bytes(num: float) -> str:
    for unit in ("o", "Ko", "Mo", "Go", "To"):
        if abs(num) < 1024:
            return f"{num:.1f} {unit}" if unit != "o" else f"{num:.0f} {unit}"
        num /= 1024
    return f"{num:.1f} Po"


def human_duration(seconds: float) -> str:
    seconds = int(seconds)
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    parts = []
    if days:
        parts.append(f"{days}j")
    if hours or days:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}min")
    return " ".join(parts)


def bar(percent: float, width: int = 10) -> str:
    filled = max(0, min(width, round(percent / 100 * width)))
    return "▰" * filled + "▱" * (width - filled)


def level_icon(percent: float, warn: float) -> str:
    if percent >= warn:
        return "🔴"
    if percent >= warn * 0.85:
        return "🟠"
    return "🟢"


def chunk_message(text: str, limit: int = TELEGRAM_MAX_LEN) -> list[str]:
    """Découpe un message en morceaux compatibles avec la limite Telegram."""
    if len(text) <= limit:
        return [text]
    chunks: list[str] = []
    current = ""
    for line in text.split("\n"):
        while len(line) > limit:
            if current:
                chunks.append(current)
                current = ""
            chunks.append(line[:limit])
            line = line[limit:]
        candidate = f"{current}\n{line}" if current else line
        if len(candidate) > limit:
            chunks.append(current)
            current = line
        else:
            current = candidate
    if current:
        chunks.append(current)
    return chunks
