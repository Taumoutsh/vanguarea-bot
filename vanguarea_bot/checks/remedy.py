"""Génère, pour chaque CVE, le correctif exact à appliquer (le bot ne modifie rien lui-même)."""

from __future__ import annotations

import json
import os
import re
import shlex
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
    """Commande copiable : en code en ligne, un appui sur Telegram mobile copie toute la commande.

    (Dans un bloc <pre>, la coloration syntaxique découpe la commande et l'appui ne copie qu'un mot.)
    """
    return f"▸ <code>{esc(cmd)}</code>"




def _steps(cmds: list[str]) -> list[str]:
    """Commandes à copier : d'un bloc (une seule ligne, s'arrête à la première erreur) ou une par une.

    Chaque commande est dans son propre bloc pour que le bouton « copier » de Telegram
    ne prenne qu'elle : un collage multi-ligne dans un terminal SSH est peu fiable.
    """
    if len(cmds) == 1:
        return [_code(cmds[0])]
    return ["📋 <i>Tout en une fois (appuyez pour copier) :</i>", _code(" && ".join(cmds)),
            "<i>ou une commande à la fois :</i>", *(_code(c) for c in cmds)]


# Paquet noyau dont le nom contient la version : linux-image-6.8.0-45-generic, linux-headers-6.1.0-18-amd64...
KERNEL_PKG = re.compile(
    r"^linux-(?P<kind>image|headers|modules(?:-extra)?)-(?:unsigned-)?(?P<release>\d+\.\d+\.\d+-\d+(?:\.\d+)?)-(?P<flavor>[a-z][a-z0-9-]*)$"
)


def _split_kernel_packages(pkgs: list[str], running_kernel: str) -> tuple[list[str], list[str], bool]:
    """Remplace les paquets noyau versionnés par leur méta-paquet.

    Un paquet « linux-image-6.8.0-45-generic » ne se met jamais à jour : le correctif arrive
    dans un nouveau paquet (6.8.0-50) installé via le méta-paquet « linux-image-generic ».
    Retourne (paquets à mettre à jour, anciens noyaux inutilisés, noyau en cours concerné).
    """
    upgrade: list[str] = []
    old: list[str] = []
    running_affected = False
    for pkg in pkgs:
        m = KERNEL_PKG.match(pkg)
        if not m:
            upgrade.append(pkg)
            continue
        if f"{m['release']}-{m['flavor']}" != running_kernel:
            old.append(pkg)
            continue
        running_affected = True
        meta = f"linux-headers-{m['flavor']}" if m["kind"] == "headers" else f"linux-image-{m['flavor']}"
        if meta not in upgrade:
            upgrade.append(meta)
    return upgrade, old, running_affected


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


def os_package_advice(pkg_type: str, fixes: dict, in_image: bool, running_kernel: str = "") -> list[str]:
    lines = [f"• <code>{esc(pkg)}</code> {esc(installed)} → <b>{esc(target)}</b> ({esc(', '.join(cves[:3]))})"
             for pkg, (installed, target, cves) in sorted(fixes.items())]
    if in_image:
        return lines

    pkgs = sorted(fixes)
    old_kernels: list[str] = []
    kernel_update = False
    if pkg_type in APT_FAMILY:
        pkgs, old_kernels, kernel_update = _split_kernel_packages(pkgs, running_kernel)
    kernel_update = kernel_update or any(p.startswith(("linux-image", "kernel", "linux-generic")) for p in pkgs)

    names = " ".join(pkgs)
    if not pkgs:
        cmds = []
    elif pkg_type in APT_FAMILY:
        cmds = ["sudo apt-get update", f"sudo apt-get install --only-upgrade -y {names}"]
    elif pkg_type in DNF_FAMILY:
        cmds = [f"sudo dnf upgrade -y {names}"]
    elif pkg_type == "alpine":
        cmds = ["apk update", f"apk upgrade {names}"]
    elif pkg_type in ("suse linux enterprise server", "opensuse.leap", "opensuse.tumbleweed"):
        cmds = [f"sudo zypper update -y {names}"]
    else:
        cmds = []
    if cmds:
        lines.append("<b>Mettre à jour</b>")
        lines += _steps(cmds)
    if old_kernels:
        lines.append(f"<b>Anciens noyaux inutilisés</b> ({esc(', '.join(old_kernels))}) : à supprimer")
        lines += _steps(["sudo apt-get autoremove --purge -y"])
    if kernel_update:
        lines.append("🔁 Nouveau noyau : redémarrer ensuite le serveur pour l'utiliser")
        lines += _steps(["sudo reboot"])
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
            lines += npm_advice(fixes, workdir, host_root)
        elif eco == "pip" and fixes:
            lines += pip_advice(fixes, workdir, host_root)
        elif eco == "go" and fixes:
            lines += go_advice(eco_vulns, workdir, host_root)
        elif fixes:
            lines.append(f"<b>{esc(eco)}</b>")
            lines += [f"• <code>{esc(p)}</code> {esc(i)} → <b>{esc(t)}</b>" for p, (i, t, _) in sorted(fixes.items())]
        if unfixable:
            lines.append(f"⏳ Pas encore de correctif ({esc(eco)}) : {esc(', '.join(unfixable))}")
    return lines


def _bullets(fixes: dict) -> list[str]:
    return [f"• <code>{esc(p)}</code> {esc(i)} → <b>{esc(t)}</b>" for p, (i, t, _) in sorted(fixes.items())]


def npm_advice(fixes: dict, workdir: Path | None, host_root: Path = Path("/")) -> list[str]:
    """npm : « npm install » pour les dépendances directes, « overrides » pour les indirectes.

    Les overrides sont écrits par une commande node d'une ligne plutôt qu'un bloc JSON à coller.
    """
    pkg_json = _find_file(workdir, "package.json") if workdir else None
    direct = _npm_direct_deps(pkg_json)
    direct_fix = {p: f for p, f in fixes.items() if p in direct}
    indirect_fix = {p: f for p, f in fixes.items() if p not in direct}
    folder = _shown(pkg_json.parent, host_root) if pkg_json else None
    lines = ["<b>npm</b>" + (f" (dans <code>{esc(folder)}</code>)" if folder else ""), *_bullets(fixes)]
    cmds = [f"cd {shlex.quote(folder)}"] if folder else []
    if direct_fix:
        cmds.append("npm install " + " ".join(f"{p}@^{t}" for p, (_, t, _) in sorted(direct_fix.items())))
    if indirect_fix:
        overrides = json.dumps({p: f"^{t}" for p, (_, t, _) in sorted(indirect_fix.items())})
        cmds.append(
            "node -e " + shlex.quote(
                'const fs=require("fs");const p=JSON.parse(fs.readFileSync("package.json"));'
                f"p.overrides={{...p.overrides,...{overrides}}};"
                'fs.writeFileSync("package.json",JSON.stringify(p,null,2)+"\\n")'
            )
        )
        cmds.append("npm install")
        lines.append("<i>Dépendances indirectes : ajout d'« overrides » dans package.json.</i>")
    return lines + _steps(cmds)


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


REQ_LINE = re.compile(r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?P<extras>\[[^\]]*\])?\s*(?P<spec>[^;#]*)(?P<rest>.*)$")
SED_REGEX_SPECIAL = re.compile(r"([\\/.*\[\]^$])")


def requirements_commands(content: str, fixes: dict[str, str], path: str) -> list[str]:
    """Commandes d'une ligne qui mettent à jour un requirements.txt (sed / printf), sans copier de bloc."""
    wanted = {_norm(p): (p, v) for p, v in fixes.items()}
    cmds: list[str] = []
    done: set[str] = set()
    for raw in content.splitlines():
        line = raw.rstrip("\r")
        if not line.strip() or line.lstrip().startswith(("#", "-")):
            continue
        m = REQ_LINE.match(line)
        if not m or _norm(m["name"]) not in wanted or _norm(m["name"]) in done:
            continue
        _, version = wanted[_norm(m["name"])]
        op = "==" if "==" in m["spec"] else ">="
        rest = m["rest"].strip()
        new = f"{m['name']}{m['extras'] or ''}{op}{version}" + (f" {rest}" if rest else "")
        done.add(_norm(m["name"]))
        old_re = SED_REGEX_SPECIAL.sub(r"\\\1", line)
        new_repl = re.sub(r"([\\/&])", r"\\\1", new)
        cmds.append(f"sed -i {shlex.quote(f's/^{old_re}\\r\\?$/{new_repl}/')} {shlex.quote(path)}")
    missing = [f"{p}>={v}" for key, (p, v) in sorted(wanted.items()) if key not in done]
    for i, req in enumerate(missing):
        # Si le fichier ne finit pas par un retour à la ligne, on en ajoute un avant la première ligne.
        fmt = "\\n%s\\n" if i == 0 and content and not content.endswith("\n") else "%s\\n"
        cmds.append(f"printf '{fmt}' {shlex.quote(req)} >> {shlex.quote(path)}")
    return cmds


def pip_advice(fixes: dict, workdir: Path | None, host_root: Path = Path("/")) -> list[str]:
    req = _find_file(workdir, "requirements.txt") if workdir else None
    if not req:
        return ["<b>Python</b> : mettre à jour dans <code>requirements.txt</code> ou <code>pyproject.toml</code>",
                *_bullets(fixes)]
    shown = _shown(req, host_root)
    try:
        content = req.read_text(errors="replace")
    except OSError:
        content = ""
    targets = {p: t for p, (_, t, _) in fixes.items()}
    return [f"<b>Python</b> : mise à jour de <code>{esc(shown)}</code>", *_bullets(fixes),
            *_steps(requirements_commands(content, targets, shown))]


def _go_module(workdir: Path | None) -> tuple[Path | None, str | None]:
    go_mod = _find_file(workdir, "go.mod") if workdir else None
    if not go_mod:
        return None, None
    try:
        m = re.search(r"^module\s+(\S+)", go_mod.read_text(), re.MULTILINE)
    except OSError:
        return go_mod, None
    return go_mod, m.group(1) if m else None


def go_advice(vulns: list[Vuln], workdir: Path | None, host_root: Path = Path("/")) -> list[str]:
    """Go : dépendances du projet (go get) ou binaires tiers embarqués dans l'image (à mettre à jour)."""
    go_mod, module = _go_module(workdir)
    by_binary: dict[str, list[Vuln]] = defaultdict(list)
    for v in vulns:
        by_binary[v.path if v.pkg_type == "gobinary" else "go.mod"].append(v)

    lines: list[str] = []
    own: list[Vuln] = []
    for binary, bvulns in sorted(by_binary.items()):
        pkgs = {v.pkg for v in bvulns}
        if binary == "go.mod" or (module and module in pkgs):
            own += bvulns
            continue
        # Binaire tiers (ex. trivy copié depuis une autre image) : on ne modifie pas son go.mod,
        # on installe une version plus récente de l'outil.
        name = binary.rstrip("/").rsplit("/", 1)[-1]
        fixes = _fixes(bvulns)
        main = next((p for p in fixes if p.rstrip("/").rsplit("/", 1)[-1] == name), None)
        lines.append(f"<b>Binaire tiers</b> <code>/{esc(binary.lstrip('/'))}</code> : {len(bvulns)} CVE")
        if main:
            lines.append(f"→ Mettre à jour <b>{esc(name)}</b> en version ≥ <b>{esc(fixes[main][1])}</b> "
                         f"(actuellement {esc(fixes[main][0])}), ex. le tag de l'image dans "
                         f"<code>COPY --from=…</code> du Dockerfile.")
        else:
            lines.append(f"→ Mettre à jour <b>{esc(name)}</b> vers sa dernière version (dépendances obsolètes).")

    if own:
        fixes = _fixes(own)
        stdlib = fixes.pop("stdlib", None)
        if fixes:
            where = f" (dans <code>{esc(_shown(go_mod.parent, host_root))}</code>)" if go_mod else ""
            lines.append(f"<b>Go</b>{where}")
            cmds = ([f"cd {_shown(go_mod.parent, host_root)}"] if go_mod else [])
            cmds += ["go get " + " ".join(f"{p}@v{t.lstrip('v')}" for p, (_, t, _) in sorted(fixes.items())),
                     "go mod tidy"]
            lines += _steps(cmds)
        if stdlib:
            lines.append(f"<b>Go stdlib</b> : compiler avec Go ≥ <b>{esc(stdlib[1])}</b> "
                         f"(ex. <code>FROM golang:{esc(stdlib[1])}</code> dans le Dockerfile)")
    return lines


def advise_host(result: TargetResult, running_kernel: str | None = None) -> str:
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
                lines += os_package_advice(pkg_type, fixes, in_image=False,
                                           running_kernel=running_kernel or os.uname().release)
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

    if ctx and not ctx.built:
        # Image tierce (postgres, nginx, redis...) : il faut une version plus récente de l'image.
        lines.append(f"Image tierce : {len(result.vulns)} CVE corrigée(s) dans une version plus récente.")
        if ctx.project:
            lines += _steps([f"cd {ctx.workdir}", f"docker compose pull {svc}", f"docker compose up -d {svc}"])
        else:
            lines += _steps([f"docker pull {result.target}"])
            lines.append(f"puis recréer le conteneur <code>{esc(ctx.container)}</code>.")
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
    steps = [f"cd {ctx.workdir}"] if ctx and ctx.workdir else []
    if lang_vulns:
        steps += ['git commit -am "fix(security): mise à jour des dépendances vulnérables"', "git push"]
    if ctx and ctx.project:
        steps += [f"docker compose build --pull{' --no-cache' if os_vulns else ''} {svc}",
                  f"docker compose up -d {svc}"]
    else:
        steps.append(f"docker build --pull -t {result.target} .")
    lines += _steps(steps)
    if not (ctx and ctx.project):
        lines.append("puis recréer le conteneur.")
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
