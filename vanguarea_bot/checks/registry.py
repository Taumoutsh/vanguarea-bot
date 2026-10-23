"""Versions plus récentes des images tierces sur leur registre public (Docker Hub, ghcr.io, quay.io...).

Deux vérifications :
- tag « mobile » (latest, 16, alpine...) : l'image publiée sous ce tag a-t-elle changé (digest différent) ?
- tag versionné (2.11.3, 16.4-alpine...) : existe-t-il un tag de version supérieure, de même forme ?
"""

from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from docker.errors import DockerException

from ..config import Config
from . import docker_check

log = logging.getLogger(__name__)

DOCKER_HUB = "registry-1.docker.io"
MAX_PAGES = 10
TAG_VERSION = re.compile(r"^(?P<prefix>v?)(?P<nums>\d+(?:\.\d+)*)(?P<suffix>(?:[-_+][A-Za-z0-9.+_-]*)?)$")
PRERELEASE = re.compile(r"(rc|alpha|beta|dev|pre|preview|nightly|snapshot|test|canary|edge)", re.IGNORECASE)


@dataclass
class ImageUpdate:
    ref: str
    tag: str
    tag_updated: bool | None = None  # une nouvelle image a été publiée sous le même tag
    newer_minor: str | None = None  # version supérieure dans la même version majeure
    newer_major: str | None = None  # version majeure supérieure
    error: str | None = None

    @property
    def available(self) -> bool:
        return bool(self.tag_updated or self.newer_minor or self.newer_major)


def parse_ref(ref: str) -> tuple[str, str, str] | None:
    """« jc21/nginx-proxy-manager:2.11 » → (registre, dépôt, tag). None pour une image locale (ID)."""
    if ref.startswith("sha256:") or "@" in ref:
        return None
    name, tag = ref, "latest"
    if ":" in ref.rsplit("/", 1)[-1]:
        name, tag = ref.rsplit(":", 1)
    first, _, rest = name.partition("/")
    if rest and ("." in first or ":" in first or first == "localhost"):
        registry, repo = first, rest
    else:
        registry, repo = DOCKER_HUB, name
    if registry in ("docker.io", "index.docker.io"):
        registry = DOCKER_HUB
    if registry == DOCKER_HUB and "/" not in repo:
        repo = f"library/{repo}"
    return registry, repo, tag


def _request(url: str, token: str | None = None):
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"} if token else {})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.headers, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers, exc.read()


def _anonymous_token(www_authenticate: str) -> str | None:
    params = dict(re.findall(r'(\w+)="([^"]*)"', www_authenticate or ""))
    if "realm" not in params:
        return None
    query = urllib.parse.urlencode({k: v for k, v in params.items() if k in ("service", "scope")})
    status, _, body = _request(f"{params['realm']}?{query}")
    if status != 200:
        return None
    data = json.loads(body)
    return data.get("token") or data.get("access_token")


def list_tags(registry: str, repo: str) -> list[str]:
    """Tags publiés (API standard /v2/<dépôt>/tags/list, jeton anonyme si nécessaire)."""
    url = f"https://{registry}/v2/{repo}/tags/list?n=1000"
    token = None
    tags: list[str] = []
    for _ in range(MAX_PAGES):
        status, headers, body = _request(url, token)
        if status == 401 and token is None:
            token = _anonymous_token(headers.get("WWW-Authenticate"))
            if token is None:
                raise RuntimeError("registre privé ou authentification requise")
            status, headers, body = _request(url, token)
        if status != 200:
            raise RuntimeError(f"registre : HTTP {status}")
        tags += json.loads(body).get("tags") or []
        link = headers.get("Link")
        m = re.search(r"<([^>]+)>;\s*rel=\"?next\"?", link or "")
        if not m:
            break
        url = urllib.parse.urljoin(url, m.group(1))
    return tags


def newer_versions(current: str, tags: list[str]) -> tuple[str | None, str | None]:
    """(version supérieure de même majeure, version majeure supérieure) parmi des tags de même forme."""
    cur = TAG_VERSION.match(current)
    if not cur:
        return None, None
    cur_nums = tuple(int(n) for n in cur["nums"].split("."))
    allow_pre = bool(PRERELEASE.search(cur["suffix"]))
    candidates = []
    for tag in tags:
        m = TAG_VERSION.match(tag)
        if not m or m["prefix"] != cur["prefix"] or m["suffix"] != cur["suffix"]:
            continue
        nums = tuple(int(n) for n in m["nums"].split("."))
        if len(nums) != len(cur_nums) or nums <= cur_nums:
            continue
        if not allow_pre and PRERELEASE.search(m["suffix"]):
            continue
        candidates.append((nums, tag))
    same_major = [c for c in candidates if c[0][0] == cur_nums[0]]
    other = [c for c in candidates if c[0][0] != cur_nums[0]]
    return (max(same_major)[1] if same_major else None), (max(other)[1] if other else None)


def _tag_updated(cfg: Config, ref: str) -> bool | None:
    """Compare le digest local au digest publié (via le démon Docker, qui gère proxy et identifiants)."""
    try:
        client = docker_check._client(cfg)
    except DockerException:
        return None
    try:
        local = {d.split("@", 1)[1] for d in client.images.get(ref).attrs.get("RepoDigests") or []}
        if not local:
            return None
        return client.images.get_registry_data(ref).id not in local
    except DockerException as exc:
        log.debug("digest %s : %s", ref, exc)
        return None
    finally:
        client.close()


def check_image(cfg: Config, ref: str) -> ImageUpdate | None:
    parsed = parse_ref(ref)
    if not parsed:
        return None
    registry, repo, tag = parsed
    update = ImageUpdate(ref, tag, tag_updated=_tag_updated(cfg, ref))
    if TAG_VERSION.match(tag):
        try:
            update.newer_minor, update.newer_major = newer_versions(tag, list_tags(registry, repo))
        except Exception as exc:  # noqa: BLE001 - registre injoignable ou privé
            update.error = str(exc)[:200]
    return update


def with_tag(ref: str, tag: str) -> str:
    """Même image avec un autre tag."""
    name = ref.rsplit(":", 1)[0] if ":" in ref.rsplit("/", 1)[-1] else ref
    return f"{name}:{tag}"
