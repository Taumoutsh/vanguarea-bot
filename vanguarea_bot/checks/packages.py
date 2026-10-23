"""Disponibilité des versions corrigées des paquets vulnérables.

- Paquets système du serveur (apt) : la version corrigée est-elle disponible dans les dépôts configurés ?
  (Trivy peut connaître un correctif pas encore publié, ou réservé à Ubuntu Pro / ESM.)
- Dépendances npm, PyPI, Go : dernière version publiée, et version corrigée réellement publiée ?
"""

from __future__ import annotations

import json
import logging
import re
import urllib.parse
import urllib.request
from dataclasses import dataclass

from ..config import Config
from ..utils import run_host_cmd
from .cve import TargetResult

log = logging.getLogger(__name__)

APT_FAMILY = {"debian", "ubuntu"}
NPM_TYPES = {"npm", "node-pkg"}
PIP_TYPES = {"pip", "python-pkg", "pipenv", "poetry"}
GO_TYPES = {"gomod", "gobinary"}
MAX_LOOKUPS = 150  # requêtes vers les registres par scan
PRERELEASE = re.compile(r"(rc|alpha|beta|dev|pre|canary|next|nightly|a\d|b\d)", re.IGNORECASE)


@dataclass
class PackageInfo:
    ecosystem: str  # apt, npm, pypi, go
    name: str
    fixed: str  # version corrigée attendue
    available: bool | None  # la version corrigée est-elle installable / publiée ?
    latest: str | None = None  # dernière version disponible (candidate apt, dernière publiée...)


def _vkey(version: str) -> tuple:
    return tuple((0, int(p)) if p.isdigit() else (-1, p) for p in re.findall(r"\d+|[a-zA-Z]+", version))


def _pick_fixed(installed: str, fixed: str) -> str:
    from .remedy import pick_fixed_version  # import local : remedy importe ce module

    return pick_fixed_version(installed, fixed) or fixed


def _get_json(url: str, headers: dict | None = None):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def _stable(versions: list[str]) -> list[str]:
    """Sans les préversions (1.0.0-beta.1, 2.0rc1...) : on ne conseille que des versions stables."""
    def suffix(v: str) -> str:
        return re.sub(r"^v?\d+(\.\d+)*", "", v)
    return [v for v in versions if not PRERELEASE.search(suffix(v))]


def registry_versions(ecosystem: str, name: str) -> list[str]:
    if ecosystem == "npm":
        data = _get_json(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}",
                         {"Accept": "application/vnd.npm.install-v1+json"})
        return list(data.get("versions", {}))
    if ecosystem == "pypi":
        data = _get_json(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json")
        return [v for v, files in data.get("releases", {}).items() if files]
    if ecosystem == "go":
        # Le proxy Go encode les majuscules en « !minuscule ».
        escaped = re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), name)
        with urllib.request.urlopen(f"https://proxy.golang.org/{escaped}/@v/list", timeout=30) as resp:
            return resp.read().decode().split()
    return []


def lang_info(ecosystem: str, name: str, installed: str, fixed: str) -> PackageInfo:
    target = _pick_fixed(installed, fixed)
    try:
        versions = _stable(registry_versions(ecosystem, name))
    except Exception as exc:  # noqa: BLE001 - registre injoignable : information inconnue
        log.debug("registre %s %s : %s", ecosystem, name, exc)
        return PackageInfo(ecosystem, name, target, None)
    if not versions:
        return PackageInfo(ecosystem, name, target, None)
    norm = {v.lstrip("v") for v in versions}
    latest = max(versions, key=lambda v: _vkey(v.lstrip("v")))
    return PackageInfo(ecosystem, name, target, target.lstrip("v") in norm, latest.lstrip("v"))


def apt_candidates(cfg: Config, pkgs: list[str]) -> dict[str, str]:
    """{paquet: version candidate} d'après les dépôts apt du serveur."""
    res = run_host_cmd(cfg, ["apt-cache", "policy", *pkgs], timeout=60)
    out: dict[str, str] = {}
    current = None
    for line in res.stdout.splitlines():
        if line and not line.startswith(" ") and line.endswith(":"):
            current = line[:-1].split(":")[0]
        elif current and line.strip().startswith("Candidate:"):
            out[current] = line.split(":", 1)[1].strip()
    return out


def dpkg_ge(cfg: Config, a: str, b: str) -> bool | None:
    res = run_host_cmd(cfg, ["dpkg", "--compare-versions", a, "ge", b], timeout=10)
    return {0: True, 1: False}.get(res.returncode)


def check(cfg: Config, results: list[TargetResult]) -> dict[str, dict]:
    """{« écosystème:paquet » : PackageInfo} pour les paquets vulnérables qui ont un correctif."""
    infos: dict[str, dict] = {}
    host = next((r for r in results if r.target == "hôte" and not r.error), None)
    if host:
        apt = {}
        for v in host.vulns:
            if v.cls == "os-pkgs" and v.pkg_type in APT_FAMILY and v.fixed:
                target = _pick_fixed(v.installed, v.fixed)
                if v.pkg not in apt or _vkey(target) > _vkey(apt[v.pkg]):
                    apt[v.pkg] = target
        if apt:
            candidates = apt_candidates(cfg, sorted(apt))
            for pkg, fixed in apt.items():
                candidate = candidates.get(pkg)
                available = dpkg_ge(cfg, candidate, fixed) if candidate and candidate != "(none)" else False
                infos[f"apt:{pkg}"] = PackageInfo("apt", pkg, fixed, available, candidate).__dict__

    wanted: dict[str, tuple[str, str, str, str]] = {}
    for r in results:
        if r.error:
            continue
        for v in r.vulns:
            eco = ("npm" if v.pkg_type in NPM_TYPES else "pypi" if v.pkg_type in PIP_TYPES
                   else "go" if v.pkg_type in GO_TYPES and v.pkg != "stdlib" else None)
            if eco and v.fixed:
                wanted.setdefault(f"{eco}:{v.pkg}", (eco, v.pkg, v.installed, v.fixed))
    for key, (eco, name, installed, fixed) in list(wanted.items())[:MAX_LOOKUPS]:
        infos[key] = lang_info(eco, name, installed, fixed).__dict__
    return infos
