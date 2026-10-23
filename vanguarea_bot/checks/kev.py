"""Catalogue CISA KEV : CVE activement exploitées par des attaquants (à corriger en urgence)."""

from __future__ import annotations

import json
import logging
import time
import urllib.request
from pathlib import Path

from ..config import Config

log = logging.getLogger(__name__)

REFRESH = 12 * 3600  # le catalogue est mis à jour quelques fois par semaine


def _cache_path(cfg: Config) -> Path:
    return cfg.state_file.parent / "kev.json"


def load(cfg: Config) -> dict[str, dict]:
    """{CVE: fiche KEV}. Téléchargé au plus toutes les 12 h, copie locale utilisée en cas d'échec."""
    path = _cache_path(cfg)
    fresh = path.exists() and time.time() - path.stat().st_mtime < REFRESH
    if not fresh:
        try:
            with urllib.request.urlopen(cfg.kev_url, timeout=60) as resp:
                raw = resp.read()
            json.loads(raw)  # on ne remplace la copie locale que par un JSON valide
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_bytes(raw)
            tmp.replace(path)
        except Exception as exc:  # noqa: BLE001 - réseau indisponible : on garde la copie locale
            log.warning("Catalogue KEV non mis à jour (%s), utilisation de la copie locale", exc)
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return {v["cveID"]: v for v in data.get("vulnerabilities", []) if v.get("cveID")}
