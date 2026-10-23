"""Recherche de CVE dans les paquets de l'hôte et les images Docker via Trivy."""

from __future__ import annotations

import json
import logging
import shutil
import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field

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
    cls: str = ""  # "os-pkgs" ou "lang-pkgs"
    pkg_type: str = ""  # debian, npm, node-pkg, pip, python-pkg, gomod, gobinary...
    path: str = ""  # fichier concerné dans l'image (lockfile, METADATA, binaire...)
    exploited: bool = False  # présente dans le catalogue CISA KEV (exploitée activement)


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
                cls=result.get("Class", ""),
                pkg_type=result.get("Type", ""),
                path=v.get("PkgPath") or result.get("Target", ""),
            )
            vulns[(vuln.pkg, vuln.cve)] = vuln
    return list(vulns.values())


# On analyse toutes les sévérités : une CVE « HIGH » ou « MEDIUM » activement exploitée est plus urgente
# qu'une « CRITICAL » théorique. Le filtrage selon CVE_SEVERITIES se fait ensuite (voir reportable).
ALL_SEVERITIES = "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"


def _scan_args(cfg: Config) -> list[str]:
    args = ["--quiet", "--cache-dir", cfg.trivy_cache_dir, "--format", "json", "--scanners", "vuln",
            "--severity", ALL_SEVERITIES, "--timeout", f"{cfg.cve_timeout}s"]
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


def mark_exploited(results: list[TargetResult], kev: dict[str, dict]) -> None:
    for r in results:
        for v in r.vulns:
            v.exploited = v.cve in kev


def reportable(results: list[TargetResult], cfg: Config) -> list[TargetResult]:
    """Garde les sévérités configurées (CVE_SEVERITIES) et, toujours, les CVE activement exploitées."""
    return [TargetResult(r.target, [v for v in r.vulns if v.severity in cfg.cve_severities or v.exploited], r.error)
            for r in results]


def record(results: list[TargetResult], state: State) -> None:
    """Enregistre le dernier scan (utilisé par /fix et par le rapport)."""
    with state.lock:
        cve_state = state.section("cve")
        cve_state.pop("seen", None)  # ancien format
        cve_state["last_scan"] = time.time()
        cve_state["last_summary"] = {
            r.target: {"error": r.error, "count": len(r.vulns),
                       "critical": sum(1 for v in r.vulns if v.severity == "CRITICAL"),
                       "exploited": sum(1 for v in r.vulns if v.exploited)}
            for r in results
        }
        cve_state["last_results"] = [asdict(r) for r in results]
        state.save()


def _key(target: str, v: Vuln) -> str:
    return f"{target}|{v.pkg}|{v.cve}"


def report_diff(state: State, update_baseline: bool) -> tuple[list[TargetResult], int, bool]:
    """CVE apparues depuis le dernier rapport quotidien (et non depuis le dernier scan).

    Retourne (nouvelles CVE, nombre de CVE corrigées ou disparues, premier rapport ?).
    La référence n'est mise à jour que par le rapport quotidien (update_baseline=True).
    """
    current = last_results(state)
    with state.lock:
        cve_state = state.section("cve")
        if not cve_state.get("last_scan"):
            return [], 0, True  # pas encore de scan : rien à comparer, la référence reste vide
        baseline_raw = cve_state.get("report_baseline")
        # Une cible dont le dernier scan a échoué garde ses CVE précédentes (ni nouvelles, ni corrigées).
        errored = {r.target for r in current if r.error}
        current_keys = {_key(r.target, v) for r in current if not r.error for v in r.vulns}
        baseline = set(baseline_raw or [])
        kept = {k for k in baseline if k.split("|", 1)[0] in errored}
        if update_baseline:
            cve_state["report_baseline"] = sorted(current_keys | kept)
            state.save()
    if baseline_raw is None:
        return [], 0, True
    new = [TargetResult(r.target, [v for v in r.vulns if _key(r.target, v) not in baseline])
           for r in current if not r.error]
    fixed = len(baseline - kept - current_keys)
    return [r for r in new if r.vulns], fixed, False


def last_results(state: State) -> list[TargetResult]:
    """Résultats complets du dernier scan (pour /fix)."""
    with state.lock:
        raw = state.data.get("cve", {}).get("last_results", [])
        return [TargetResult(r["target"], [Vuln(**v) for v in r["vulns"]], r.get("error")) for r in raw]


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
        ordered = sorted(by_pkg.items(), key=lambda kv: (-any(v.exploited for v in kv[1]),
                                                           -sum(v.severity == "CRITICAL" for v in kv[1]), kv[0][0]))
        for (pkg, installed, fixed), vulns in ordered[:max_per_target]:
            icon = ("🔥" if any(v.exploited for v in vulns)
                    else "🔴" if any(v.severity == "CRITICAL" for v in vulns) else "🟠")
            fix = f"→ <b>{esc(fixed)}</b>" if fixed else "(pas de correctif)"
            cves = ", ".join(f'<a href="{esc(v.url)}">{esc(v.cve)}</a>' for v in vulns[:5])
            if len(vulns) > 5:
                cves += f" +{len(vulns) - 5}"
            lines.append(f"{icon} <code>{esc(pkg)}</code> {esc(installed)} {fix}\n     {cves}")
        if len(ordered) > max_per_target:
            lines.append(f"   … et {len(ordered) - max_per_target} autre(s) paquet(s)")
    if any(v.exploited for r in results for v in r.vulns):
        lines.append("")
        lines.append("🔥 = activement exploitée par des attaquants (catalogue CISA KEV) : à corriger en priorité")
    if any(r.vulns for r in results):
        lines.append("")
        lines.append("💡 /fix pour le correctif détaillé de chaque projet")
    return "\n".join(lines)
