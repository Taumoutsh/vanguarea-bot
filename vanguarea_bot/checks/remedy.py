"""Génère, pour chaque CVE, le correctif exact à appliquer (le bot ne modifie rien lui-même)."""

from __future__ import annotations

import json
import os
import re
import shlex
from collections import defaultdict
from collections.abc import Callable
from pathlib import Path

from ..config import Config
from ..utils import copy_steps as _steps, esc, run_host_cmd
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
    lines = _bullets(fixes)
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
        lines += ["", "🔧 <b>Mettre à jour</b>", *_steps(cmds)]
    if old_kernels:
        lines += ["", f"🗑 <b>Anciens noyaux inutilisés</b> : {esc(', '.join(old_kernels))}",
                  *_steps(["sudo apt-get autoremove --purge -y"])]
    if kernel_update:
        lines += ["", "🔁 <b>Nouveau noyau</b> : redémarrer ensuite le serveur", *_steps(["sudo reboot"])]
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
            lines += ["", f"📦 <b>{esc(eco)}</b>", *_bullets(fixes)]
        if unfixable:
            lines.append(f"⏳ Pas encore de correctif ({esc(eco)}) : {esc(', '.join(unfixable))}")
    return lines


def _bullets(fixes: dict, limit: int = 6) -> list[str]:
    """Paquets à mettre à jour (les premiers seulement, pour rester lisible)."""
    items = sorted(fixes.items())
    lines = [f"• <code>{esc(p)}</code> {esc(i)} → <b>{esc(t)}</b>" for p, (i, t, _) in items[:limit]]
    if len(items) > limit:
        lines.append(f"• … et {len(items) - limit} autre(s) paquet(s)")
    return lines


def npm_advice(fixes: dict, workdir: Path | None, host_root: Path = Path("/")) -> list[str]:
    """npm : « npm install » pour les dépendances directes, « overrides » pour les indirectes.

    Les overrides sont écrits par une commande node d'une ligne plutôt qu'un bloc JSON à coller.
    """
    pkg_json = _find_file(workdir, "package.json") if workdir else None
    direct = _npm_direct_deps(pkg_json)
    direct_fix = {p: f for p, f in fixes.items() if p in direct}
    indirect_fix = {p: f for p, f in fixes.items() if p not in direct}
    folder = _shown(pkg_json.parent, host_root) if pkg_json else (_shown(workdir, host_root) if workdir else None)
    lines = ["", "📦 <b>npm</b>" + (f" — <code>{esc(folder)}</code>" if folder else ""), *_bullets(fixes)]
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
    lines.append("🔧 <b>Mettre à jour</b>")
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
        return ["", "📦 <b>Python</b> — à mettre à jour dans <code>requirements.txt</code> ou <code>pyproject.toml</code>",
                *_bullets(fixes)]
    shown = _shown(req, host_root)
    try:
        content = req.read_text(errors="replace")
    except OSError:
        content = ""
    targets = {p: t for p, (_, t, _) in fixes.items()}
    return ["", f"📦 <b>Python</b> — <code>{esc(shown)}</code>", *_bullets(fixes), "🔧 <b>Mettre à jour</b>",
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
        lines += ["", f"📦 <b>Binaire tiers</b> <code>/{esc(binary.lstrip('/'))}</code> — {len(bvulns)} CVE"]
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
            where = f" — <code>{esc(_shown(go_mod.parent, host_root))}</code>" if go_mod else ""
            lines += ["", f"📦 <b>Go</b>{where}", "🔧 <b>Mettre à jour</b>"]
            cmds = ([f"cd {_shown(go_mod.parent, host_root)}"] if go_mod else [])
            cmds += ["go get " + " ".join(f"{p}@v{t.lstrip('v')}" for p, (_, t, _) in sorted(fixes.items())),
                     "go mod tidy"]
            lines += _steps(cmds)
        if stdlib:
            lines.append(f"📦 <b>Go stdlib</b> : compiler avec Go ≥ <b>{esc(stdlib[1])}</b> "
                         f"(ex. <code>FROM golang:{esc(stdlib[1])}</code> dans le Dockerfile)")
    return lines


# Dossiers gérés par un outil (éditeur, IDE...) : leurs dépendances se corrigent en mettant l'outil à jour.
TOOL_DIRS = [
    (".vscode-server-insiders", "VS Code Server (Insiders) et ses extensions"),
    (".vscode-server", "VS Code Server et ses extensions"),
    (".cursor-server", "Cursor Server et ses extensions"),
    (".cache/JetBrains", "IDE JetBrains (GoLand, IntelliJ…)"),
    (".local/share/JetBrains", "IDE JetBrains (GoLand, IntelliJ…)"),
    (".npm/_npx", "Cache npx"),
    (".cache/ms-playwright", "Navigateurs Playwright"),
]


def _short(path: str) -> str:
    """Chemin raccourci pour l'affichage : /home/ubuntu/x → ~/x."""
    return re.sub(r"^/home/[^/]+", "~", path)


def _host_origin(path: str) -> tuple[str, str, str]:
    """(dossier racine, libellé, type) d'une dépendance trouvée sur le serveur."""
    p = "/" + path.lstrip("/")
    for marker, label in TOOL_DIRS:
        idx = p.find(f"/{marker}/")
        if idx != -1:
            return p[: idx + len(marker) + 1], label, "tool"
    if "/node_modules/" in p:
        return p[: p.index("/node_modules/")], "Projet Node.js", "npm"
    for marker in ("/site-packages/", "/dist-packages/"):
        if marker in p:
            root = p[: p.index(marker)]
            if root.startswith("/usr/"):
                return root, "Python du système", "pip-system"
            return re.sub(r"/lib/python[^/]*$", "", root), "Environnement Python", "pip"
    return p, "Fichier", "other"


def package_owner(cfg: Config, path: str) -> tuple[str, str] | None:
    """Paquet système qui a installé un fichier : ("apt", "docker-compose-plugin"), ("dnf", ...) ou None."""
    res = run_host_cmd(cfg, ["dpkg-query", "-S", path], timeout=20)
    if res.ok and res.stdout.strip():
        line = next((l for l in res.stdout.splitlines() if not l.startswith("diversion")), "")
        pkg = line.split(": ", 1)[0].split(",")[0].strip()
        if pkg:
            return "apt", re.sub(r":[a-z0-9_]+$", "", pkg)  # sans le suffixe d'architecture (:amd64)
    res = run_host_cmd(cfg, ["rpm", "-qf", "--qf", "%{NAME}\n", path], timeout=20)
    if res.ok and res.stdout.strip() and "not owned" not in res.stdout:
        return "dnf", res.stdout.split()[0]
    return None


def _owned_files_advice(owned: dict[tuple[str, str], list[tuple[str, int]]]) -> list[str]:
    """Binaires installés par des paquets système : mise à jour de ces paquets."""
    lines = ["", "📦 <b>Binaires installés par des paquets système</b>"]
    for (_, pkg), files in sorted(owned.items()):
        for path, count in files:
            lines.append(f"• <code>{esc(pkg)}</code> — {esc(path.rsplit('/', 1)[-1])} ({count} CVE)")
    by_manager: dict[str, list[str]] = defaultdict(list)
    for manager, pkg in sorted(owned):
        by_manager[manager].append(pkg)
    lines.append("🔧 <b>Mettre à jour</b>")
    for manager, pkgs in by_manager.items():
        if manager == "apt":
            lines += _steps(["sudo apt-get update", "sudo apt-get install --only-upgrade -y " + " ".join(pkgs)])
        else:
            lines += _steps(["sudo dnf upgrade -y " + " ".join(pkgs)])
    lines.append("<i>Ce sont des bibliothèques compilées dans ces binaires : si les CVE restent après la mise à "
                 "jour, l'éditeur n'a pas encore publié de version corrigée.</i>")
    return lines


def host_lang_advice(vulns: list[Vuln], host_root: Path = Path("/"),
                     owner_of: Callable[[str], tuple[str, str] | None] | None = None) -> list[str]:
    """Dépendances applicatives du serveur, regroupées par origine (outil, projet, environnement Python)."""
    groups: dict[tuple[str, str, str], list[Vuln]] = defaultdict(list)
    for v in vulns:
        groups[_host_origin(v.path)].append(v)

    lines: list[str] = []
    owned: dict[tuple[str, str], list[tuple[str, int]]] = {}
    for (root, label, kind), gvulns in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        fixes = _fixes(gvulns)
        pkgs = sorted({v.pkg for v in gvulns})
        if kind == "tool":
            names = ", ".join(pkgs[:5]) + (f" +{len(pkgs) - 5}" if len(pkgs) > 5 else "")
            lines += ["", f"🧩 <b>{esc(label)}</b> — <code>{esc(_short(root))}</code>",
                      f"{len(gvulns)} CVE dans ses dépendances internes ({esc(names)}).",
                      "<i>Gérées par l'outil lui-même : mettez à jour l'outil et ses extensions, "
                      "puis supprimez les anciennes versions restées en cache avec /cleanup.</i>"]
        elif kind == "npm" and fixes:
            lines += npm_advice(fixes, host_root / root.lstrip("/"), host_root)
        elif kind == "pip" and fixes:
            cmd = f"{shlex.quote(root + '/bin/pip')} install " + " ".join(
                shlex.quote(f"{p}>={t}") for p, (_, t, _) in sorted(fixes.items()))
            lines += ["", f"📦 <b>{esc(label)}</b> — <code>{esc(_short(root))}</code>", *_bullets(fixes),
                      "🔧 <b>Mettre à jour</b>", *_steps([cmd]),
                      "<i>Pensez à reporter les versions dans le requirements.txt du projet.</i>"]
        elif kind == "pip-system":
            lines += ["", f"📦 <b>{esc(label)}</b> — <code>{esc(root)}</code>", *_bullets(fixes),
                      "<i>Installés par les paquets du système : corrigés par les mises à jour apt.</i>"]
        else:
            owner = owner_of(root) if owner_of else None
            if owner:
                owned.setdefault(owner, []).append((root, len(gvulns)))
                continue
            lines += ["", f"📦 <b>{esc(label)}</b> — <code>{esc(_short(root))}</code>", *_bullets(fixes),
                      "<i>Installé hors gestionnaire de paquets : mettez à jour le logiciel qui l'a installé, "
                      "ou supprimez-le s'il ne sert plus.</i>"]
    if owned:
        lines += _owned_files_advice(owned)
    return lines


def advise_host(result: TargetResult, running_kernel: str | None = None, host_root: Path = Path("/"),
                owner_of: Callable[[str], tuple[str, str] | None] | None = None) -> str:
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
        lines += host_lang_advice(lang_vulns, host_root, owner_of)
    return "\n".join(lines)


def _tag(ref: str) -> str | None:
    """Tag d'une référence d'image (« latest » pour « nginx:latest »), None si c'est un ID."""
    if ref.startswith("sha256:"):
        return None
    name = ref.rsplit("/", 1)[-1]
    return name.split(":", 1)[1] if ":" in name else "latest"


def advise_image(cfg: Config, result: TargetResult, contexts: list[ImageContext]) -> str:
    ctx = contexts[0] if contexts else None
    services = sorted({c.service for c in contexts if c.service})
    label = f"{ctx.project} / {', '.join(services)}" if ctx and ctx.project else result.target
    lines = [f"🐳 <b>{esc(label)}</b>", f"<i>{esc(result.target)}</i>"]

    os_vulns = [v for v in result.vulns if v.cls == "os-pkgs"]
    lang_vulns = [v for v in result.vulns if v.cls != "os-pkgs"]
    workdir = cfg.host_path(ctx.workdir) if ctx and ctx.workdir else None
    svc = " ".join(services)

    if ctx and not ctx.built:
        # Image tierce (postgres, nginx, redis...) : il faut une version plus récente de l'image.
        n = len(result.vulns)
        lines += ["", f"Image tierce — <b>{n} CVE</b> corrigée{'s' if n > 1 else ''} dans une version plus récente.",
                  "", "🔧 <b>Mettre à jour</b>"]
        if ctx.project:
            lines += _steps([f"cd {ctx.workdir}", f"docker compose pull {svc}", f"docker compose up -d {svc}"])
        else:
            lines += _steps([f"docker pull {result.target}"])
            lines.append(f"puis recréer le conteneur <code>{esc(ctx.container)}</code>.")
        if _tag(result.target) == "latest":
            lines.append("<i>Si les CVE persistent après la mise à jour, l'éditeur n'a pas encore publié "
                         "d'image corrigée : réessayez plus tard.</i>")
        else:
            lines.append("<i>Si les CVE persistent après la mise à jour, la version est figée par le tag : "
                         "montez-la dans le docker-compose.yml.</i>")
        return "\n".join(lines)

    if os_vulns:
        by_type: dict[str, list[Vuln]] = defaultdict(list)
        for v in os_vulns:
            by_type[v.pkg_type].append(v)
        lines += ["", "📦 <b>Paquets système de l'image</b>"]
        for pkg_type, vulns in by_type.items():
            fixes = _fixes(vulns)
            if fixes:
                lines += os_package_advice(pkg_type, fixes, in_image=True)
        lines.append("<i>Corrigés en reconstruisant l'image (ci-dessous). Si ça ne suffit pas, montez la "
                     "version du FROM du Dockerfile.</i>")
    if lang_vulns:
        lines += lang_advice(lang_vulns, workdir, cfg.host_root)

    lines += ["", "🚀 <b>Redéployer</b>"]
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
                blocks.append(advise_host(r, host_root=cfg.host_root, owner_of=lambda p: package_owner(cfg, p)))
            continue
        ctxs = contexts.get(r.target, [])
        if project and not any(project in (c.project, c.service, c.container) for c in ctxs) and project != r.target:
            continue
        blocks.append(advise_image(cfg, r, ctxs))
    if not blocks:
        return ["✅ Aucun correctif à appliquer" + (f" pour <b>{esc(project)}</b>." if project else ".")]
    header = ("🛠 <b>Correctifs à appliquer</b>\n\n"
              "👆 Appuyez sur une commande pour la copier.\n"
              "▸ La ligne affichée lance tout d'un coup ; « Commande par commande » (à déplier) les détaille.\n"
              "<i>Vérifiez puis testez chaque changement avant de le déployer.</i>")
    return [header, *blocks]
