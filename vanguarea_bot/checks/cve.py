"""Recherche de CVE dans les paquets de l'hôte et les images Docker via Trivy."""

from __future__ import annotations

import json
import logging
import shutil
import time
from collections import defaultdict
from dataclasses import dataclass, field

from ..config import Config
from ..state import State
from ..utils import esc, run_cmd
from . import docker_check

log = logging.getLogger(__name__)

# Répertoires à ignorer lors du scan du système de fichiers de l'hôte :
# les couches Docker sont analysées image par image.
SKIP_DIRS = [
    "/proc", "/sys", "/dev", "/run", "/tmp", "/var/tmp",
    "/var/lib/docker", "/var/lib/containerd", "/var/lib/containers", "/snap",
]


@dataclass
class Vuln:
    cve: str
    severity: str
    pkg: str
    installed: str
    fixed: str
    title: str
    url: str


@dataclass
class TargetResult:
    target: str  # "hôte" ou nom de l'image
    vulns: list[Vuln] = field(default_factory=list)
    error: str | None = None


def parse_trivy_json(raw: str) -> list[Vuln]:
    data = json.loads(raw)
    vulns: dict[tuple[str, str], Vuln] = {}
    for result in data.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            vuln = Vuln(
                cve=v.get("VulnerabilityID", "?"),
                severity=v.get("Severity", "UNKNOWN"),
                pkg=v.get("PkgName", "?"),
                installed=v.get("InstalledVersion", "?"),
                fixed=v.get("FixedVersion", ""),
                title=(v.get("Title") or "").strip(),
                url=v.get("PrimaryURL") or f"https://avd.aquasec.com/nvd/{v.get('VulnerabilityID', '').lower()}",
            )
            vulns[(vuln.pkg, vuln.cve)] = vuln
    return list(vulns.values())


def _scan_args(cfg: Config) -> list[str]:
    args = ["--quiet", "--cache-dir", cfg.trivy_cache_dir, "--format", "json", "--scanners", "vuln",
            "--severity", ",".join(cfg.cve_severities), "--timeout", f"{cfg.cve_timeout}s"]
    if cfg.cve_ignore_unfixed:
        args.append("--ignore-unfixed")
    return args


def scan_host(cfg: Config) -> TargetResult:
    skip: list[str] = []
    for d in SKIP_DIRS:
        skip += ["--skip-dirs", d]
        if cfg.containerized:
            skip += ["--skip-dirs", str(cfg.host_path(d))]
    if not cfg.containerized:
        skip += ["--skip-dirs", cfg.trivy_cache_dir]
    args = [cfg.trivy_bin, "rootfs", *_scan_args(cfg), *skip, str(cfg.host_root)]
    return _run(cfg, "hôte", args)


def scan_image(cfg: Config, image: str) -> TargetResult:
    args = [cfg.trivy_bin, "image", *_scan_args(cfg), image]
    return _run(cfg, image, args)


def _run(cfg: Config, target: str, args: list[str]) -> TargetResult:
    log.info("Scan Trivy : %s", target)
    res = run_cmd(args, timeout=cfg.cve_timeout + 60)
    if not res.ok:
        err = (res.stderr.strip().splitlines() or ["erreur inconnue"])[-1]
        return TargetResult(target, error=err[:300])
    try:
        return TargetResult(target, parse_trivy_json(res.stdout))
    except json.JSONDecodeError as exc:
        return TargetResult(target, error=f"sortie JSON invalide : {exc}")


def trivy_available(cfg: Config) -> bool:
    return shutil.which(cfg.trivy_bin) is not None


def scan_all(cfg: Config) -> list[TargetResult]:
    results: list[TargetResult] = []
    if cfg.cve_scan_host:
        results.append(scan_host(cfg))
    if cfg.cve_scan_images:
        try:
            images = docker_check.running_images(cfg)
        except Exception as exc:  # noqa: BLE001 - Docker peut être absent
            results.append(TargetResult("docker", error=str(exc)))
            images = []
        for image in images:
            results.append(scan_image(cfg, image))
    return results


def record_and_diff(results: list[TargetResult], state: State) -> list[TargetResult]:
    """Enregistre le scan et retourne uniquement les vulnérabilités nouvelles."""
    with state.lock:
        cve_state = state.section("cve")
        seen = set(cve_state.get("seen", []))
        current: set[str] = set()
        new_results = []
        for r in results:
            new = []
            for v in r.vulns:
                key = f"{r.target}|{v.pkg}|{v.cve}"
                current.add(key)
                if key not in seen:
                    new.append(v)
            if new:
                new_results.append(TargetResult(r.target, new))
        # On ne garde que ce qui est encore présent : une CVE corrigée puis réintroduite sera re-signalée.
        cve_state["seen"] = sorted(current)
        cve_state["last_scan"] = time.time()
        cve_state["last_summary"] = {
            r.target: {"error": r.error, "count": len(r.vulns),
                       "critical": sum(1 for v in r.vulns if v.severity == "CRITICAL")}
            for r in results
        }
        state.save()
    return new_results


def format_results(results: list[TargetResult], title: str, max_per_target: int = 15) -> str:
    total = sum(len(r.vulns) for r in results)
    lines = [f"🛡 <b>{esc(title)}</b> — {total} vulnérabilité(s)"]
    for r in results:
        lines.append("")
        if r.error:
            lines.append(f"❌ <b>{esc(r.target)}</b> : scan impossible\n<code>{esc(r.error)}</code>")
            continue
        if not r.vulns:
            lines.append(f"✅ <b>{esc(r.target)}</b> : rien à signaler")
            continue
        lines.append(f"📦 <b>{esc(r.target)}</b> : {len(r.vulns)} CVE")
        by_pkg: dict[tuple[str, str, str], list[Vuln]] = defaultdict(list)
        for v in r.vulns:
            by_pkg[(v.pkg, v.installed, v.fixed)].append(v)
        ordered = sorted(by_pkg.items(), key=lambda kv: (-sum(v.severity == "CRITICAL" for v in kv[1]), kv[0][0]))
        for (pkg, installed, fixed), vulns in ordered[:max_per_target]:
            icon = "🔴" if any(v.severity == "CRITICAL" for v in vulns) else "🟠"
            fix = f"→ <b>{esc(fixed)}</b>" if fixed else "(pas de correctif)"
            cves = ", ".join(f'<a href="{esc(v.url)}">{esc(v.cve)}</a>' for v in vulns[:5])
            if len(vulns) > 5:
                cves += f" +{len(vulns) - 5}"
            lines.append(f"{icon} <code>{esc(pkg)}</code> {esc(installed)} {fix}\n     {cves}")
        if len(ordered) > max_per_target:
            lines.append(f"   … et {len(ordered) - max_per_target} autre(s) paquet(s)")
    if any(r.vulns for r in results):
        lines.append("")
        lines.append("💡 Hôte : <code>apt update &amp;&amp; apt upgrade</code> — "
                     "Images : mettre à jour l'image puis <code>docker compose pull &amp;&amp; up -d</code>")
    return "\n".join(lines)
