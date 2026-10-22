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


def copy_cmd(cmd: str) -> str:
    """Commande copiable : en code en ligne, un appui sur Telegram mobile copie toute la commande.

    (Dans un bloc <pre>, la coloration syntaxique découpe la commande et l'appui ne copie qu'un mot.)
    """
    return f"▸ <code>{esc(cmd)}</code>"


def copy_steps(cmds: list[str]) -> list[str]:
    """Commandes à copier : toutes sur une ligne (s'arrête à la première erreur), et le détail
    commande par commande replié dans un bloc dépliable pour garder le message lisible.

    Chaque commande est sur sa propre ligne en code en ligne : un appui la copie en entier.
    """
    if len(cmds) == 1:
        return [copy_cmd(cmds[0])]
    detail = "\n".join(["<i>Commande par commande :</i>", *(copy_cmd(c) for c in cmds)])
    return [copy_cmd(" && ".join(cmds)), f"<blockquote expandable>{detail}</blockquote>"]


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


def _units(text: str) -> list[str]:
    """Lignes du message, un bloc <blockquote> comptant pour une seule unité (jamais coupé en deux)."""
    units: list[str] = []
    current: list[str] | None = None
    for line in text.split("\n"):
        if current is not None:
            current.append(line)
            if "</blockquote>" in line:
                units.append("\n".join(current))
                current = None
        elif "<blockquote" in line and "</blockquote>" not in line:
            current = [line]
        else:
            units.append(line)
    if current is not None:
        units.append("\n".join(current))
    return units


def chunk_message(text: str, limit: int = TELEGRAM_MAX_LEN) -> list[str]:
    """Découpe un message en morceaux compatibles avec la limite Telegram (sans casser le HTML des citations)."""
    if len(text) <= limit:
        return [text]
    chunks: list[str] = []
    current = ""
    for unit in _units(text):
        while len(unit) > limit:
            if current:
                chunks.append(current)
                current = ""
            chunks.append(unit[:limit])
            unit = unit[limit:]
        candidate = f"{current}\n{unit}" if current else unit
        if len(candidate) > limit:
            chunks.append(current)
            current = unit
        else:
            current = candidate
    if current:
        chunks.append(current)
    return chunks
