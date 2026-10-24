"""Informations sur une adresse IP : pays, ville, opérateur, nom DNS (ipinfo.io ou RDAP), avec cache."""

from __future__ import annotations

import ipaddress
import json
import logging
import socket
import time
import urllib.parse
import urllib.request

from ..config import Config
from ..state import State
from ..utils import esc

log = logging.getLogger(__name__)

CACHE_TTL = 30 * 86400
MAX_CACHE = 2000


def flag(country: str | None) -> str:
    """« FR » → 🇫🇷"""
    if not country or len(country) != 2 or not country.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in country.upper())


def _get_json(url: str):
    with urllib.request.urlopen(urllib.request.Request(url, headers={"Accept": "application/json"}),
                                timeout=15) as resp:
        return json.loads(resp.read())


def _reverse_dns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return None


def _ipinfo(cfg: Config, ip: str) -> dict:
    query = f"?token={urllib.parse.quote(cfg.ipinfo_token)}" if cfg.ipinfo_token else ""
    data = _get_json(f"https://ipinfo.io/{ip}/json{query}")
    org = data.get("org") or ""
    if org.startswith("AS") and " " in org:
        org = org.split(" ", 1)[1]  # « AS12322 Free SAS » → « Free SAS »
    return {"country": data.get("country"), "city": data.get("city"), "org": org or None,
            "hostname": data.get("hostname")}


def _rdap(ip: str) -> dict:
    data = _get_json(f"https://rdap.org/ip/{ip}")
    org = None
    for entity in data.get("entities") or []:
        if "registrant" in (entity.get("roles") or []):
            for item in (entity.get("vcardArray") or [None, []])[1]:
                if item and item[0] == "fn":
                    org = item[3]
                    break
    return {"country": data.get("country"), "city": None, "org": org or data.get("name"),
            "hostname": _reverse_dns(ip)}


def lookup(cfg: Config, state: State, ip: str) -> dict:
    """Infos sur une IP (dict vide si désactivé ou indisponible). Réseau local : {"local": True}."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {}
    if not addr.is_global:
        return {"local": True}
    if cfg.geoip_provider == "none":
        return {}
    with state.lock:
        cache = state.section("geoip")
        hit = cache.get(ip)
        if hit and time.time() - hit.get("ts", 0) < CACHE_TTL:
            return hit
    try:
        info = _rdap(ip) if cfg.geoip_provider == "rdap" else _ipinfo(cfg, ip)
    except Exception as exc:  # noqa: BLE001 - service injoignable : on s'en passe
        log.debug("géolocalisation %s : %s", ip, exc)
        return {}
    info["ts"] = time.time()
    with state.lock:
        cache[ip] = info
        if len(cache) > MAX_CACHE:
            for old in sorted(cache, key=lambda k: cache[k].get("ts", 0))[: len(cache) - MAX_CACHE]:
                del cache[old]
    return info


def describe(ip: str, info: dict) -> str:
    """« 🇫🇷 FR, Lyon · Free SAS · box-1.fbx.proxad.net »"""
    if info.get("local"):
        return f"<code>{esc(ip)}</code> (réseau local)"
    parts = []
    place = ", ".join(p for p in (info.get("country"), info.get("city")) if p)
    if place:
        parts.append(f"{flag(info.get('country'))} {esc(place)}".strip())
    if info.get("org"):
        parts.append(esc(info["org"]))
    if info.get("hostname"):
        parts.append(f"<code>{esc(info['hostname'])}</code>")
    return f"<code>{esc(ip)}</code>" + (" — " + " · ".join(parts) if parts else "")
