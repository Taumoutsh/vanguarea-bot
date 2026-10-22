"""Détection de l'espace disque récupérable et commandes de nettoyage à proposer.

Le bot ne supprime rien lui-même : il liste ce qui peut l'être et donne les commandes.
« Sans risque » = versions obsolètes ou caches reconstruits automatiquement ;
« à vérifier » = données potentiellement utiles (volumes, conteneurs arrêtés, logs).
"""

from __future__ import annotations

import glob
import logging
import os
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path

from ..config import Config
from ..utils import copy_steps, esc, human_bytes, run_host_cmd
from . import docker_check

log = logging.getLogger(__name__)

MIN_SIZE = 50 * 1024 * 1024  # on ne propose rien en dessous de 50 Mo

# Versions de serveurs d'éditeurs distants : on garde la plus récente (et celles en cours d'utilisation).
EDITOR_SERVER_DIRS = [
    ("VS Code Server", ".vscode-server/bin/*"),
    ("VS Code Server", ".vscode-server/cli/servers/*"),
    ("VS Code CLI", ".vscode-server/code-*"),
    ("VS Code Server (Insiders)", ".vscode-server-insiders/bin/*"),
    ("VS Code Server (Insiders)", ".vscode-server-insiders/cli/servers/*"),
    ("VS Code tunnel", ".vscode/cli/servers/*"),
    ("Cursor Server", ".cursor-server/bin/*"),
    ("Cursor Server", ".cursor-server/cli/servers/*"),
    ("JetBrains (GoLand, IntelliJ…) – backend distant", ".cache/JetBrains/RemoteDev/dist/*"),
]
EXTENSION_DIRS = [".vscode-server/extensions", ".cursor-server/extensions"]
# Caches par version de produit JetBrains : GoLand2024.3, IntelliJIdea2025.1...
JETBRAINS_VERSIONED_DIRS = [".cache/JetBrains", ".local/share/JetBrains"]
JETBRAINS_PRODUCT = re.compile(r"^(?P<product>[A-Za-z]+)(?P<version>\d{4}\.\d+)$")
EXTENSION_VERSION = re.compile(r"^(?P<name>.+?)-(?P<version>\d+\.\d+\.\d+.*)$")

# Caches reconstruits automatiquement à la demande.
CACHES = [
    ("Cache de compilation Go", ".cache/go-build"),
    ("Cache des modules Go (re-téléchargés au besoin)", "go/pkg/mod"),
    ("Cache gopls / golangci-lint", ".cache/gopls"),
    ("Cache gopls / golangci-lint", ".cache/golangci-lint"),
    ("Cache npm", ".npm/_cacache"),
    ("Cache Yarn", ".cache/yarn"),
    ("Cache pip", ".cache/pip"),
]


@dataclass
class Item:
    title: str
    size: int | None
    details: list[str] = field(default_factory=list)
    cmds: list[str] = field(default_factory=list)
    safe: bool = True
    note: str = ""


def dir_size(path: Path) -> int:
    """Espace réellement occupé sur le disque (comme ``du``), sans suivre les liens."""
    try:
        st = path.lstat()
    except OSError:
        return 0
    if not path.is_dir() or path.is_symlink():
        return st.st_blocks * 512
    total = 0
    for root, dirs, files in os.walk(path, onerror=lambda e: None):
        for name in dirs + files:
            try:
                total += os.lstat(os.path.join(root, name)).st_blocks * 512
            except OSError:
                pass
    return total


def _shown(cfg: Config, path: Path) -> str:
    """Chemin vu depuis l'hôte (sans le préfixe HOST_ROOT du conteneur)."""
    try:
        return "/" + str(path.relative_to(cfg.host_root))
    except ValueError:
        return str(path)


def _homes(cfg: Config) -> list[Path]:
    homes = [cfg.host_path("/root")] + [Path(p) for p in sorted(glob.glob(str(cfg.host_path("/home/*"))))]
    return [h for h in homes if h.is_dir()]


def _running_cmdlines() -> str:
    """Lignes de commande des processus de l'hôte, pour ne jamais proposer un dossier en cours d'utilisation."""
    out = []
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as fh:
                out.append(fh.read().replace(b"\0", b" ").decode(errors="replace"))
        except OSError:
            continue
    return "\n".join(out)


def _rm(paths: list[str]) -> str:
    return "sudo rm -rf " + " ".join(shlex.quote(p) for p in paths)


def _old_versions(cfg: Config, candidates: list[Path], running: str) -> list[Path]:
    """Toutes les entrées sauf la plus récente et celles utilisées par un processus en cours."""
    candidates = sorted(candidates, key=lambda p: p.lstat().st_mtime, reverse=True)
    return [p for p in candidates[1:] if _shown(cfg, p) not in running]


def _item_for_paths(cfg: Config, title: str, paths: list[Path], note: str = "", safe: bool = True) -> Item | None:
    sizes = {p: dir_size(p) for p in paths}
    total = sum(sizes.values())
    if not paths or total < MIN_SIZE:
        return None
    shown = [_shown(cfg, p) for p in sorted(paths, key=lambda p: -sizes[p])]
    details = [f"<code>{esc(s)}</code> ({human_bytes(sizes[p])})"
               for s, p in zip(shown, sorted(paths, key=lambda p: -sizes[p]))]
    return Item(title, total, details, [_rm(shown)], safe, note)


def editor_items(cfg: Config, running: str) -> list[Item]:
    items: list[Item] = []
    for home in _homes(cfg):
        old_by_title: dict[str, list[Path]] = {}
        for title, pattern in EDITOR_SERVER_DIRS:
            entries = [Path(p) for p in glob.glob(str(home / pattern))]
            old_by_title.setdefault(title, []).extend(_old_versions(cfg, entries, running))

        # SDK téléchargés par des extensions (ex. agent-host/sdk-cache/claude/<version>) : une liste par SDK.
        for sdk in sorted(glob.glob(str(home / ".vscode-server/data/agent-host/sdk-cache/*"))):
            entries = [Path(p) for p in glob.glob(f"{sdk}/*") if Path(p).is_dir()]
            old_by_title.setdefault("SDK en cache des extensions VS Code", []).extend(
                _old_versions(cfg, entries, running))

        for ext_dir in EXTENSION_DIRS:
            groups: dict[str, list[Path]] = {}
            for p in (home / ext_dir).glob("*"):
                m = EXTENSION_VERSION.match(p.name)
                if p.is_dir() and m:
                    groups.setdefault(m["name"], []).append(p)
            for versions in groups.values():
                old_by_title.setdefault("Anciennes versions d'extensions VS Code", []).extend(
                    _old_versions(cfg, versions, running))

        for base in JETBRAINS_VERSIONED_DIRS:
            groups = {}
            for p in (home / base).glob("*"):
                m = JETBRAINS_PRODUCT.match(p.name)
                if p.is_dir() and m:
                    groups.setdefault(m["product"], []).append(p)
            for versions in groups.values():
                versions.sort(key=lambda p: [int(x) for x in JETBRAINS_PRODUCT.match(p.name)["version"].split(".")])
                old = [p for p in versions[:-1] if _shown(cfg, p) not in running]
                old_by_title.setdefault("JetBrains – caches d'anciennes versions", []).extend(old)

        for title, paths in old_by_title.items():
            item = _item_for_paths(cfg, f"{title} ({_shown(cfg, home)})", paths,
                                   "Anciennes versions : la plus récente est conservée.")
            if item:
                items.append(item)
    return items


def cache_items(cfg: Config) -> list[Item]:
    items: list[Item] = []
    for home in _homes(cfg):
        by_title: dict[str, list[Path]] = {}
        for title, rel in CACHES:
            path = home / rel
            if path.is_dir():
                by_title.setdefault(title, []).append(path)
        for title, paths in by_title.items():
            item = _item_for_paths(cfg, f"{title} ({_shown(cfg, home)})", paths,
                                   "Cache reconstruit automatiquement à la prochaine utilisation.")
            if item:
                items.append(item)
    return items


def docker_items(cfg: Config) -> list[Item]:
    client = docker_check._client(cfg)
    try:
        df = client.df()
    finally:
        client.close()
    items: list[Item] = []

    unused = [i for i in df.get("Images") or [] if i.get("Containers", 0) == 0]
    size = sum(max(i.get("Size", 0) - max(i.get("SharedSize", 0), 0), 0) for i in unused)
    if size >= MIN_SIZE:
        unused.sort(key=lambda i: -i.get("Size", 0))
        details = [f"<code>{esc((i.get('RepoTags') or ['<sans tag>'])[0])}</code> ({human_bytes(i.get('Size', 0))})"
                   for i in unused]
        items.append(Item("Images Docker inutilisées", size, details, ["docker image prune -a -f"],
                          note="Images utilisées par aucun conteneur (même arrêté) ; re-téléchargeables."))

    cache = sum(b.get("Size", 0) for b in df.get("BuildCache") or [] if not b.get("InUse"))
    if cache >= MIN_SIZE:
        items.append(Item("Cache de build Docker", cache, [], ["docker builder prune -a -f"],
                          note="Ralentit seulement le prochain build."))

    stopped = [c for c in df.get("Containers") or [] if c.get("State") in ("exited", "created", "dead")]
    if stopped:
        names = [c["Names"][0].lstrip("/") for c in stopped]
        size = sum(c.get("SizeRw", 0) or 0 for c in stopped)
        items.append(Item("Conteneurs arrêtés", size, [f"<code>{esc(n)}</code>" for n in names],
                          ["docker rm " + " ".join(shlex.quote(n) for n in names)], safe=False,
                          note="Vérifiez qu'il ne s'agit pas de conteneurs arrêtés volontairement."))

    volumes = [v for v in df.get("Volumes") or [] if (v.get("UsageData") or {}).get("RefCount", 1) == 0]
    size = sum(max((v.get("UsageData") or {}).get("Size", 0), 0) for v in volumes)
    if volumes and size >= MIN_SIZE:
        volumes.sort(key=lambda v: -(v.get("UsageData") or {}).get("Size", 0))
        details = [f"<code>{esc(v['Name'])}</code> ({human_bytes(max(v['UsageData'].get('Size', 0), 0))})"
                   for v in volumes]
        items.append(Item("Volumes Docker non utilisés", size, details,
                          ["docker volume rm " + " ".join(shlex.quote(v["Name"]) for v in volumes)], safe=False,
                          note="⚠️ Un volume contient des DONNÉES (bases de données…) : suppression définitive. "
                               "Ne supprimez que ceux d'anciens projets."))

    big_logs = []
    for path in glob.glob(str(cfg.host_path("/var/lib/docker/containers/*/*-json.log"))):
        size = dir_size(Path(path))
        if size >= 100 * 1024 * 1024:
            big_logs.append((Path(path), size))
    if big_logs:
        shown = [_shown(cfg, p) for p, _ in big_logs]
        items.append(Item("Logs de conteneurs volumineux", sum(s for _, s in big_logs),
                          [f"<code>{esc(s)}</code> ({human_bytes(size)})" for s, (_, size) in zip(shown, big_logs)],
                          ["sudo truncate -s 0 " + " ".join(shlex.quote(s) for s in shown)], safe=False,
                          note="Efface l'historique de docker logs. Pour éviter que ça revienne : option "
                               "logging max-size dans le docker-compose.yml."))
    return items


def system_items(cfg: Config) -> list[Item]:
    items: list[Item] = []
    apt_cache = cfg.host_path("/var/cache/apt/archives")
    size = sum(dir_size(p) for p in apt_cache.glob("*.deb")) if apt_cache.is_dir() else 0
    if size >= MIN_SIZE:
        items.append(Item("Cache des paquets apt", size, [], ["sudo apt-get clean"],
                          note="Paquets .deb déjà installés."))

    res = run_host_cmd(cfg, ["apt-get", "-s", "-o", "Debug::NoLocking=1", "-o", "Dir::Cache::pkgcache=",
                             "-o", "Dir::Cache::srcpkgcache=", "autoremove"], timeout=120)
    if res.ok:
        pkgs = [line.split()[1] for line in res.stdout.splitlines() if line.startswith("Remv ")]
        if pkgs:
            items.append(Item(f"{len(pkgs)} paquet(s) apt devenu(s) inutile(s)", None,
                              [esc(", ".join(pkgs[:30])) + (" …" if len(pkgs) > 30 else "")],
                              ["sudo apt-get autoremove --purge -y"],
                              note="Dépendances qui ne sont plus nécessaires (dont les anciens noyaux)."))

    journal = cfg.host_path("/var/log/journal")
    size = dir_size(journal) if journal.is_dir() else 0
    if size >= 500 * 1024 * 1024:
        items.append(Item("Journaux systemd (journald)", size - 200 * 1024 * 1024, [],
                          ["sudo journalctl --vacuum-size=200M"], note="Conserve les 200 Mo les plus récents."))

    res = run_host_cmd(cfg, ["snap", "list", "--all"], timeout=30)
    if res.ok:
        old = []
        for line in res.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 3 and "disabled" in line:
                name, rev = parts[0], parts[2]
                old.append((name, rev, dir_size(cfg.host_path(f"/var/lib/snapd/snaps/{name}_{rev}.snap"))))
        if old:
            items.append(Item("Anciennes révisions snap", sum(s for *_, s in old),
                              [f"<code>{esc(n)}</code> rév. {esc(r)}" for n, r, _ in old],
                              [f"sudo snap remove {shlex.quote(n)} --revision={shlex.quote(r)}" for n, r, _ in old]))

    rotated = []
    for root, _, files in os.walk(cfg.host_path("/var/log"), onerror=lambda e: None):
        for name in files:
            if name.endswith(".gz") or re.search(r"\.\d+$", name):
                rotated.append(Path(root, name))
    size = sum(dir_size(p) for p in rotated)
    if size >= 200 * 1024 * 1024:
        items.append(Item("Anciens logs archivés (/var/log)", size, [f"{len(rotated)} fichier(s)"],
                          ['sudo find /var/log -type f \\( -name "*.gz" -o -regex ".*\\.[0-9]+" \\) -delete'],
                          safe=False, note="Perte de l'historique des logs (utile en cas d'incident de sécurité)."))
    return items


def collect(cfg: Config) -> list[Item]:
    running = _running_cmdlines()
    items: list[Item] = []
    for name, func in (("éditeurs", lambda: editor_items(cfg, running)), ("caches", lambda: cache_items(cfg)),
                       ("docker", lambda: docker_items(cfg)), ("système", lambda: system_items(cfg))):
        try:
            items += func()
        except Exception:  # noqa: BLE001 - une source en erreur ne doit pas empêcher les autres
            log.exception("Analyse de nettoyage « %s » en erreur", name)
    return sorted(items, key=lambda i: (not i.safe, -(i.size or 0)))


def reclaimable(items: list[Item]) -> tuple[int, int]:
    """(total récupérable, dont sans risque)."""
    total = sum(i.size or 0 for i in items)
    return total, sum(i.size or 0 for i in items if i.safe)


def format_cleanup(items: list[Item]) -> str:
    if not items:
        return "🧹 Rien d'important à nettoyer ✅"
    total, safe = reclaimable(items)
    lines = [f"🧹 <b>Nettoyage possible</b> — ~{human_bytes(total)} récupérables, "
             f"dont <b>{human_bytes(safe)} sans risque</b>"]
    for safe_section, title in ((True, "✅ <b>Sans risque</b>"), (False, "⚠️ <b>À vérifier avant de supprimer</b>")):
        section = [i for i in items if i.safe == safe_section]
        if not section:
            continue
        lines += ["", title]
        for item in section:
            size = f" — {human_bytes(item.size)}" if item.size else ""
            lines += ["", f"<b>{esc(item.title)}</b>{size}"]
            lines += [f"• {d}" for d in item.details[:8]]
            if len(item.details) > 8:
                lines.append(f"• … et {len(item.details) - 8} autre(s)")
            if item.note:
                lines.append(f"<i>{esc(item.note)}</i>")
            lines += copy_steps(item.cmds)
    safe_cmds = [c for i in items if i.safe for c in i.cmds]
    if len(safe_cmds) > 1:
        lines += ["", "🧹 <b>Tout le nettoyage sans risque en une fois</b>", *copy_steps([" && ".join(safe_cmds)])]
    lines += ["", "💡 Contrôlez l'espace libéré avec <code>df -h /</code>"]
    return "\n".join(lines)
