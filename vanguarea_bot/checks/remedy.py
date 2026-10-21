"""Génère, pour chaque CVE, le correctif exact à appliquer (le bot ne modifie rien lui-même)."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path

from ..config import Config
from ..utils import esc
from .cve import TargetResult, Vuln
from .docker_check import ImageContext

APT_FAMILY = {"debian", "ubuntu"}
DNF_FAMILY = {"redhat", "centos", "rocky", "alma", "almalinux", "amazon", "oracle", "fedora", "photon", "azurelinux"}
NPM_TYPES = {"npm", "node-pkg"}
PIP_TYPES = {"pip", "python-pkg", "pipenv", "poetry"}
GO_TYPES = {"gomod", "gobinary"}
SKIP_DIRS = {"node_modules", ".git", "vendor", "venv", ".venv", "dist", "build", "__pycache__"}


def _vkey(version: str) -> tuple:
    return tuple((0, int(p)) if p.isdigit() else (-1, p) for p in re.findall(r"\d+|[a-zA-Z]+", version))


def _major(version: str) -> str:
    m = re.match(r"v?(\d+)", version.strip())
    return m.group(1) if m else ""


def pick_fixed_version(installed: str, fixed: str) -> str | None:
    """Plus petite version corrigée, de préférence dans la même version majeure.

    Trivy peut proposer plusieurs versions : « 1.2.5, 2.0.1 ».
    """
    candidates = [c.strip().lstrip(">=v ").strip() for c in re.split(r"[,|]", fixed)]
    candidates = [c for c in candidates if c]
    if not candidates:
        return None
    newer = [c for c in candidates if _vkey(c) >= _vkey(installed.lstrip("v"))]
    same_major = [c for c in newer if _major(c) == _major(installed)]
    return min(same_major or newer or candidates, key=_vkey)


def _fixes(vulns: list[Vuln]) -> dict[str, tuple[str, str, list[str]]]:
    """{paquet: (version installée, version cible, [CVE])} pour les vulnérabilités corrigeables."""
    out: dict[str, tuple[str, str, list[str]]] = {}
    for v in vulns:
        target = pick_fixed_version(v.installed, v.fixed) if v.fixed else None
        if not target:
            continue
        if v.pkg in out:
            installed, best, cves = out[v.pkg]
            out[v.pkg] = (installed, max(best, target, key=_vkey), cves + [v.cve])
        else:
            out[v.pkg] = (v.installed, target, [v.cve])
    return out


def _code(cmd: str) -> str:
    return f"<pre>{esc(cmd)}</pre>"


def _find_file(root: Path, name: str, depth: int = 2) -> Path | None:
    if (root / name).is_file():
        return root / name
    if depth == 0 or not root.is_dir():
        return None
    try:
        children = sorted(p for p in root.iterdir() if p.is_dir() and p.name not in SKIP_DIRS)
    except OSError:
        return None
    for child in children:
        found = _find_file(child, name, depth - 1)
        if found:
            return found
    return None


def _npm_direct_deps(package_json: Path | None) -> set[str]:
    if not package_json:
        return set()
    try:
        data = json.loads(package_json.read_text())
    except (OSError, json.JSONDecodeError):
        return set()
    deps: set[str] = set()
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        deps |= set((data.get(section) or {}).keys())
    return deps


def os_package_advice(pkg_type: str, fixes: dict, in_image: bool) -> list[str]:
    pkgs = " ".join(sorted(fixes))
    if pkg_type in APT_FAMILY:
        cmd = f"sudo apt-get update && sudo apt-get install --only-upgrade {pkgs}"
    elif pkg_type in DNF_FAMILY:
        cmd = f"sudo dnf upgrade {pkgs}"
    elif pkg_type == "alpine":
        cmd = f"apk upgrade {pkgs}"
    elif pkg_type in ("suse linux enterprise server", "opensuse.leap", "opensuse.tumbleweed"):
        cmd = f"sudo zypper update {pkgs}"
    else:
        cmd = None
    lines = []
    for pkg, (installed, target, cves) in sorted(fixes.items()):
        lines.append(f"• <code>{esc(pkg)}</code> {esc(installed)} → <b>{esc(target)}</b> ({esc(', '.join(cves[:3]))})")
    if not in_image and cmd:
        lines.append(_code(cmd))
    if not in_image and any(p.startswith(("linux-image", "kernel", "linux-generic")) for p in fixes):
        lines.append("🔁 Mise à jour du noyau : redémarrage nécessaire (<code>sudo reboot</code>).")
    return lines


def _shown(path: Path, host_root: Path) -> str:
    """Chemin tel qu'on le voit sur l'hôte (sans le préfixe HOST_ROOT du conteneur)."""
    try:
        return "/" + str(path.relative_to(host_root))
    except ValueError:
        return str(path)


def lang_advice(vulns: list[Vuln], workdir: Path | None, host_root: Path = Path("/")) -> list[str]:
    """Correctifs pour les dépendances applicatives (npm, pip, Go, autres)."""
    lines: list[str] = []
    by_eco: dict[str, list[Vuln]] = defaultdict(list)
    for v in vulns:
        eco = ("npm" if v.pkg_type in NPM_TYPES else "pip" if v.pkg_type in PIP_TYPES
               else "go" if v.pkg_type in GO_TYPES else v.pkg_type or "autre")
        by_eco[eco].append(v)

    for eco, eco_vulns in sorted(by_eco.items()):
        fixes = _fixes(eco_vulns)
        unfixable = sorted({v.pkg for v in eco_vulns if v.pkg not in fixes})
        if eco == "npm" and fixes:
            pkg_json = _find_file(workdir, "package.json") if workdir else None
            direct = _npm_direct_deps(pkg_json)
            where = f" (dans <code>{esc(_shown(pkg_json.parent, host_root))}</code>)" if pkg_json else ""
            direct_fix = {p: f for p, f in fixes.items() if p in direct}
            indirect_fix = {p: f for p, f in fixes.items() if p not in direct}
            lines.append(f"<b>npm</b>{where}")
            if direct_fix:
                lines.append(_code("npm install " + " ".join(f"{p}@^{t}" for p, (_, t, _) in sorted(direct_fix.items()))))
            if indirect_fix:
                overrides = json.dumps({p: f"^{t}" for p, (_, t, _) in sorted(indirect_fix.items())}, indent=2)
                lines.append("Dépendances indirectes : ajouter dans <code>package.json</code> puis <code>npm install</code> :")
                lines.append(_code(f'"overrides": {overrides}'))
        elif eco == "pip" and fixes:
            req = _find_file(workdir, "requirements.txt") if workdir else None
            where = f"<code>{esc(_shown(req, host_root))}</code>" if req else "<code>requirements.txt</code> (ou pyproject.toml)"
            lines.append(f"<b>Python</b> : mettre à jour {where}")
            lines.append(_code("\n".join(f"{p}>={t}" for p, (_, t, _) in sorted(fixes.items()))))
        elif eco == "go" and fixes:
            stdlib = fixes.pop("stdlib", None)
            if fixes:
                cmds = [f"go get {p}@v{t.lstrip('v')}" for p, (_, t, _) in sorted(fixes.items())] + ["go mod tidy"]
                lines.append("<b>Go</b>")
                lines.append(_code("\n".join(cmds)))
            if stdlib:
                lines.append(f"<b>Go stdlib</b> : compiler avec Go ≥ <b>{esc(stdlib[1])}</b> "
                             f"(ex. <code>FROM golang:{esc(stdlib[1])}</code> dans le Dockerfile)")
        elif fixes:
            lines.append(f"<b>{esc(eco)}</b>")
            lines += [f"• <code>{esc(p)}</code> {esc(i)} → <b>{esc(t)}</b>" for p, (i, t, _) in sorted(fixes.items())]
        if unfixable:
            lines.append(f"⏳ Pas encore de correctif ({esc(eco)}) : {esc(', '.join(unfixable))}")
    return lines


def advise_host(result: TargetResult) -> str:
    lines = ["🖥 <b>Serveur</b>"]
    os_vulns = [v for v in result.vulns if v.cls == "os-pkgs"]
    lang_vulns = [v for v in result.vulns if v.cls != "os-pkgs"]
    if os_vulns:
        by_type: dict[str, list[Vuln]] = defaultdict(list)
        for v in os_vulns:
            by_type[v.pkg_type].append(v)
        for pkg_type, vulns in by_type.items():
            fixes = _fixes(vulns)
            if fixes:
                lines += os_package_advice(pkg_type, fixes, in_image=False)
    if lang_vulns:
        lines.append("Dépendances applicatives installées sur le serveur :")
        for v in lang_vulns:
            lines.append(f"• <code>{esc(v.pkg)}</code> {esc(v.installed)} → <b>{esc(v.fixed or '?')}</b> "
                         f"— <code>{esc(v.path)}</code>")
    return "\n".join(lines)


def advise_image(cfg: Config, result: TargetResult, contexts: list[ImageContext]) -> str:
    ctx = contexts[0] if contexts else None
    services = sorted({c.service for c in contexts if c.service})
    label = f"{ctx.project} / {', '.join(services)}" if ctx and ctx.project else result.target
    lines = [f"🐳 <b>{esc(label)}</b> — <i>{esc(result.target)}</i>"]

    os_vulns = [v for v in result.vulns if v.cls == "os-pkgs"]
    lang_vulns = [v for v in result.vulns if v.cls != "os-pkgs"]
    workdir = cfg.host_path(ctx.workdir) if ctx and ctx.workdir else None
    svc = " ".join(services)
    cd = f"cd {ctx.workdir} && " if ctx and ctx.workdir else ""

    if ctx and not ctx.built:
        # Image tierce (postgres, nginx, redis...) : il faut une version plus récente de l'image.
        lines.append(f"Image tierce : {len(result.vulns)} CVE corrigée(s) dans une version plus récente.")
        if ctx.project:
            lines.append(_code(f"{cd}docker compose pull {svc}\n{cd}docker compose up -d {svc}"))
        else:
            lines.append(_code(f"docker pull {result.target}  # puis recréer le conteneur {ctx.container}"))
        lines.append("Si la CVE persiste après le pull, le tag est figé : passez à une version plus récente "
                     "de l'image dans votre docker-compose.yml.")
        return "\n".join(lines)

    if os_vulns:
        by_type: dict[str, list[Vuln]] = defaultdict(list)
        for v in os_vulns:
            by_type[v.pkg_type].append(v)
        lines.append("<b>Paquets système de l'image</b>")
        for pkg_type, vulns in by_type.items():
            fixes = _fixes(vulns)
            if fixes:
                lines += os_package_advice(pkg_type, fixes, in_image=True)
        lines.append("→ Reconstruire en récupérant l'image de base à jour. Si ça ne suffit pas, "
                     "monter la version du <code>FROM</code> du Dockerfile (image de base obsolète).")
    if lang_vulns:
        lines += lang_advice(lang_vulns, workdir, cfg.host_root)

    lines.append("")
    lines.append("<b>Puis redéployer</b>")
    steps = []
    if lang_vulns:
        steps.append(f'{cd}git commit -am "fix(security): mise à jour des dépendances vulnérables" && git push')
    if ctx and ctx.project:
        steps.append(f"{cd}docker compose build --pull{' --no-cache' if os_vulns else ''} {svc}")
        steps.append(f"{cd}docker compose up -d {svc}")
    else:
        steps.append(f"docker build --pull -t {result.target} .  # puis recréer le conteneur")
    lines.append(_code("\n".join(steps)))
    return "\n".join(lines)


def advise(cfg: Config, results: list[TargetResult], contexts: dict[str, list[ImageContext]],
           project: str | None = None) -> list[str]:
    """Correctifs pour tous les résultats (ou un seul projet), un message par cible."""
    blocks = []
    for r in results:
        if r.error or not r.vulns:
            continue
        if r.target == "hôte":
            if project in (None, "hôte", "serveur", "host"):
                blocks.append(advise_host(r))
            continue
        ctxs = contexts.get(r.target, [])
        if project and not any(project in (c.project, c.service, c.container) for c in ctxs) and project != r.target:
            continue
        blocks.append(advise_image(cfg, r, ctxs))
    if not blocks:
        return ["✅ Aucun correctif à appliquer" + (f" pour <b>{esc(project)}</b>." if project else ".")]
    header = "🛠 <b>Correctifs à appliquer</b>\n<i>Vérifiez puis testez chaque changement avant de le déployer.</i>"
    return [header, *blocks]
