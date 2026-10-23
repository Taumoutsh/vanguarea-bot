"""Surveillance des conteneurs Docker."""

from __future__ import annotations

import logging
import shlex
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone

import docker
from docker.errors import DockerException

from ..config import Config
from ..state import CRITICAL, WARNING, Alert, State
from ..utils import copy_steps, esc, human_bytes, human_duration

log = logging.getLogger(__name__)


@dataclass
class ContainerInfo:
    name: str
    image: str
    status: str  # running, exited, restarting, paused, dead, created
    health: str | None
    exit_code: int
    restart_count: int
    oom_killed: bool
    mem_usage: int | None = None
    mem_limit: int | None = None
    cpu_percent: float | None = None
    project: str | None = None
    oneoff: bool = False  # conteneur ponctuel créé par « docker compose run »
    started_at: float | None = None


def _client(cfg: Config) -> docker.DockerClient:
    return docker.DockerClient(base_url=cfg.docker_url, timeout=30)


def _cpu_percent(stats: dict) -> float | None:
    try:
        cpu = stats["cpu_stats"]
        pre = stats["precpu_stats"]
        cpu_delta = cpu["cpu_usage"]["total_usage"] - pre["cpu_usage"]["total_usage"]
        sys_delta = cpu["system_cpu_usage"] - pre["system_cpu_usage"]
        ncpu = cpu.get("online_cpus") or len(cpu["cpu_usage"].get("percpu_usage") or [1])
        if sys_delta > 0 and cpu_delta >= 0:
            return cpu_delta / sys_delta * ncpu * 100
    except (KeyError, TypeError):
        pass
    return None


def _parse_time(value: str | None) -> float | None:
    """Horodatage Docker (« 2026-10-22T20:09:36.92106902Z ») en secondes depuis l'epoch."""
    if not value or value.startswith("0001-"):
        return None
    try:
        return datetime.strptime(value[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None


def parse_container(attrs: dict) -> ContainerInfo:
    st = attrs.get("State", {})
    image = attrs.get("Config", {}).get("Image") or attrs.get("Image", "?")
    labels = attrs.get("Config", {}).get("Labels") or {}
    return ContainerInfo(
        name=attrs.get("Name", "?").lstrip("/"),
        image=image,
        status=st.get("Status", "unknown"),
        health=(st.get("Health") or {}).get("Status"),
        exit_code=st.get("ExitCode", 0),
        restart_count=attrs.get("RestartCount", 0),
        oom_killed=bool(st.get("OOMKilled")),
        project=labels.get("com.docker.compose.project"),
        oneoff=labels.get("com.docker.compose.oneoff", "").lower() == "true",
        started_at=_parse_time(st.get("StartedAt")),
    )


def collect(cfg: Config, with_stats: bool = False) -> list[ContainerInfo]:
    client = _client(cfg)
    try:
        containers = client.containers.list(all=True)
        infos = [parse_container(c.attrs) for c in containers]
        if with_stats:
            running = [(c, i) for c, i in zip(containers, infos) if i.status == "running"]

            def fill(pair):
                container, info = pair
                try:
                    stats = container.stats(stream=False)
                    mem = stats.get("memory_stats", {})
                    cache = mem.get("stats", {}).get("inactive_file", 0)
                    info.mem_usage = max(0, mem.get("usage", 0) - cache) if mem.get("usage") else None
                    info.mem_limit = mem.get("limit")
                    info.cpu_percent = _cpu_percent(stats)
                except DockerException as exc:
                    log.debug("stats %s : %s", info.name, exc)

            with ThreadPoolExecutor(max_workers=8) as pool:
                list(pool.map(fill, running))
        return sorted(infos, key=lambda i: i.name)
    finally:
        client.close()


def running_images(cfg: Config) -> list[str]:
    """Images utilisées par les conteneurs en cours d'exécution (tag ou ID)."""
    client = _client(cfg)
    try:
        refs: dict[str, str] = {}
        for c in client.containers.list():
            image = c.image
            ref = image.tags[0] if image.tags else image.id
            refs[image.id] = ref
        return sorted(set(refs.values()))
    finally:
        client.close()


@dataclass
class ImageContext:
    """Où une image est utilisée : projet docker compose, service, dossier, construite localement ou non."""

    ref: str
    container: str
    project: str | None
    service: str | None
    workdir: str | None
    built: bool
    config_files: str | None = None  # fichiers docker-compose (séparés par des virgules)


def image_contexts(cfg: Config) -> dict[str, list[ImageContext]]:
    client = _client(cfg)
    try:
        out: dict[str, list[ImageContext]] = {}
        for c in client.containers.list():
            image = c.image
            ref = image.tags[0] if image.tags else image.id
            labels = c.labels or {}
            out.setdefault(ref, []).append(ImageContext(
                ref=ref,
                container=c.name,
                project=labels.get("com.docker.compose.project"),
                service=labels.get("com.docker.compose.service"),
                workdir=labels.get("com.docker.compose.project.working_dir"),
                # Une image construite localement n'a pas de digest de registre.
                built=not image.attrs.get("RepoDigests"),
                config_files=labels.get("com.docker.compose.project.config_files"),
            ))
        return out
    finally:
        client.close()


ONEOFF_MAX_AGE = 3600  # une tâche « compose run » encore active après 1 h est probablement bloquée


def oneoff_alerts(containers: list[ContainerInfo], now: float | None = None) -> list[Alert]:
    """Une alerte par projet pour les conteneurs ponctuels (« docker compose run ») qui s'accumulent.

    Ces conteneurs héritent du healthcheck du service (qui teste l'API) alors qu'ils exécutent une tâche :
    ils sont donc presque toujours « unhealthy ». On ne les signale pas un par un.
    """
    now = time.time() if now is None else now
    by_project: dict[str, list[ContainerInfo]] = {}
    for c in containers:
        if c.oneoff:
            by_project.setdefault(c.project or "?", []).append(c)
    out: list[Alert] = []
    for project, items in sorted(by_project.items()):
        stuck = [c for c in items if c.status == "running" and c.started_at and now - c.started_at >= ONEOFF_MAX_AGE]
        failed = [c for c in items if c.status == "exited" and c.exit_code != 0]
        if not stuck and not failed:
            continue
        lines = []
        if stuck:
            oldest = max(now - c.started_at for c in stuck)
            lines.append(f"• <b>{len(stuck)}</b> encore actif(s) depuis plus d'1 h (le plus ancien : "
                         f"{human_duration(oldest)})")
        if failed:
            lines.append(f"• <b>{len(failed)}</b> terminé(s) en erreur, non supprimé(s)")
        filters = (f"--filter label=com.docker.compose.oneoff=True "
                   f"--filter label=com.docker.compose.project={shlex.quote(project)}")
        lines += ["", "<i>Créés par « docker compose run » (cron, script…) : lancez-les avec --rm, ou utilisez "
                      "« docker compose exec » pour une tâche dans le service déjà démarré.</i>",
                  "🔎 <b>Voir ce qu'ils exécutent</b>",
                  *copy_steps([f"docker ps -a {filters} --format '{{{{.Names}}}} | {{{{.Status}}}} | "
                               f"{{{{.Command}}}}'"]),
                  "🗑 <b>Les supprimer</b>",
                  *copy_steps([f"docker ps -aq {filters} | xargs -r docker rm -f"])]
        out.append(Alert(f"docker:oneoff:{project}", WARNING,
                         f"Tâches « docker compose run » qui s'accumulent ({esc(project)})", "\n".join(lines)))
    return out


def alerts(containers: list[ContainerInfo], cfg: Config, state: State) -> list[Alert]:
    out: list[Alert] = oneoff_alerts([c for c in containers if c.name not in cfg.docker_ignore])
    with state.lock:
        restarts = state.section("docker_restart_counts")
        for c in containers:
            if c.name in cfg.docker_ignore or c.oneoff:
                continue
            label = f"Conteneur <code>{esc(c.name)}</code>"
            if c.oom_killed:
                out.append(Alert(f"docker:oom:{c.name}", CRITICAL, f"{label} tué par manque de mémoire (OOM)",
                                 f"Image : {esc(c.image)}"))
            if c.status == "dead":
                out.append(Alert(f"docker:dead:{c.name}", CRITICAL, f"{label} est en état « dead »"))
            elif c.status == "restarting":
                out.append(Alert(f"docker:restarting:{c.name}", CRITICAL, f"{label} redémarre en boucle",
                                 f"Redémarrages : {c.restart_count} — dernier code de sortie : {c.exit_code}"))
            elif c.status == "exited" and c.exit_code != 0:
                out.append(Alert(f"docker:exited:{c.name}", WARNING, f"{label} est arrêté (code {c.exit_code})",
                                 f"Image : {esc(c.image)}"))
            if c.health == "unhealthy":
                out.append(Alert(f"docker:unhealthy:{c.name}", CRITICAL, f"{label} est <i>unhealthy</i>"))

            previous = restarts.get(c.name)
            if previous is not None and c.restart_count > previous and c.status != "restarting":
                out.append(Alert(f"docker:restart:{c.name}:{c.restart_count}", WARNING,
                                 f"{label} a redémarré ({c.restart_count - previous} fois)",
                                 f"Code de sortie précédent : {c.exit_code}", stateful=False))
            restarts[c.name] = c.restart_count

        names = {c.name for c in containers}
        for name in [n for n in restarts if n not in names]:
            del restarts[name]
    return out


STATUS_ICONS = {"running": "🟢", "exited": "⚫", "restarting": "🔄", "paused": "⏸", "dead": "💀", "created": "⚪"}


def format_containers(containers: list[ContainerInfo]) -> str:
    running = sum(1 for c in containers if c.status == "running")
    lines = [f"🐳 <b>Docker</b> — {running}/{len(containers)} conteneur(s) actif(s)", ""]
    for c in containers:
        icon = STATUS_ICONS.get(c.status, "❔")
        if c.health == "unhealthy":
            icon = "🔴"
        line = f"{icon} <b>{esc(c.name)}</b>"
        details = ["tâche compose run"] if c.oneoff else []
        if c.status != "running":
            details.append(f"{c.status} ({c.exit_code})")
        if c.health:
            details.append(c.health)
        if c.cpu_percent is not None:
            details.append(f"CPU {c.cpu_percent:.1f}%")
        if c.mem_usage is not None:
            details.append(f"RAM {human_bytes(c.mem_usage)}")
        if c.restart_count:
            details.append(f"{c.restart_count} redémarrage(s)")
        if details:
            line += " — " + esc(", ".join(details))
        line += f"\n    <i>{esc(c.image)}</i>"
        lines.append(line)
    return "\n".join(lines)
