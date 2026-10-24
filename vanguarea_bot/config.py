"""Configuration chargée depuis les variables d'environnement."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import time
from pathlib import Path


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return default
    return value.strip()


def _int(name: str, default: int) -> int:
    return int(_env(name, str(default)))


def _float(name: str, default: float) -> float:
    return float(_env(name, str(default)))


def _bool(name: str, default: bool) -> bool:
    return _env(name, "true" if default else "false").lower() in ("1", "true", "yes", "on", "oui")


def _list(name: str, default: str = "") -> list[str]:
    raw = _env(name, default) or ""
    return [item.strip() for item in raw.split(",") if item.strip()]


def _time(name: str, default: str) -> time:
    hours, minutes = (_env(name, default) or default).split(":")
    return time(int(hours), int(minutes))


DEFAULT_WATCHED_FILES = ",".join(
    [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/sudoers",
        "/etc/sudoers.d",
        "/etc/ssh/sshd_config",
        "/etc/ssh/sshd_config.d",
        "/etc/crontab",
        "/etc/cron.d",
        "/root/.ssh/authorized_keys",
        "/home/*/.ssh/authorized_keys",
        "/etc/ld.so.preload",
    ]
)


@dataclass(frozen=True)
class Config:
    token: str
    chat_ids: frozenset[int]
    timezone: str = "Europe/Paris"
    host_root: Path = Path("/")
    server_name: str = ""
    state_file: Path = Path("/data/state.json")
    docker_url: str = "unix:///var/run/docker.sock"

    # Fréquences
    check_interval: int = 300
    security_interval: int = 60
    alert_cooldown: int = 3600
    daily_report_time: time = time(8, 0)
    cve_scan_interval: float = 6.0  # heures entre deux scans (silencieux, résumés dans le rapport quotidien)

    # Seuils système
    cpu_threshold: float = 90.0
    mem_threshold: float = 90.0
    swap_threshold: float = 80.0
    disk_threshold: float = 85.0
    inode_threshold: float = 85.0
    load_threshold: float = 2.0  # charge 5 min / nombre de CPU

    # Docker
    docker_ignore: tuple[str, ...] = ()

    # CVE / Trivy
    trivy_bin: str = "trivy"
    trivy_cache_dir: str = "/data/trivy-cache"
    cve_severities: tuple[str, ...] = ("CRITICAL",)
    cve_ignore_unfixed: bool = True
    cve_scan_host: bool = True
    cve_scan_images: bool = True
    cve_timeout: int = 3600
    kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    auto_stop_exploited: bool = False  # arrêter les conteneurs touchés par une CVE activement exploitée
    auto_stop_exclude: tuple[str, ...] = ("vanguarea-bot",)

    # Sécurité
    ssh_fail_threshold: int = 15
    ssh_trusted_ips: tuple[str, ...] = ()
    geoip_provider: str = "ipinfo"  # ipinfo (pays, ville, opérateur), rdap (sans ville, sans limite) ou none
    ipinfo_token: str = ""
    syn_recv_threshold: int = 200
    conn_per_ip_threshold: int = 150
    rx_pps_threshold: int = 50_000
    rx_mbps_threshold: float = 500.0
    access_logs: tuple[str, ...] = ()
    http_rate_threshold: int = 600
    http_scan_threshold: int = 20
    watched_files: tuple[str, ...] = field(default_factory=tuple)

    @property
    def containerized(self) -> bool:
        return str(self.host_root) != "/"

    def host_path(self, path: str) -> Path:
        """Chemin d'un fichier de l'hôte (préfixé par HOST_ROOT en mode conteneur)."""
        return self.host_root / path.lstrip("/")


def load_config() -> Config:
    token = _env("TELEGRAM_BOT_TOKEN")
    if not token:
        raise SystemExit("TELEGRAM_BOT_TOKEN est obligatoire")
    chat_ids = frozenset(int(c) for c in _list("TELEGRAM_CHAT_IDS"))
    if not chat_ids:
        raise SystemExit("TELEGRAM_CHAT_IDS est obligatoire (identifiants séparés par des virgules)")

    return Config(
        token=token,
        chat_ids=chat_ids,
        timezone=_env("TZ", "Europe/Paris"),
        host_root=Path(_env("HOST_ROOT", "/")),
        server_name=_env("SERVER_NAME", ""),
        state_file=Path(_env("STATE_FILE", "/data/state.json")),
        docker_url=_env("DOCKER_HOST", "unix:///var/run/docker.sock"),
        check_interval=_int("CHECK_INTERVAL", 300),
        security_interval=_int("SECURITY_INTERVAL", 60),
        alert_cooldown=_int("ALERT_COOLDOWN", 3600),
        daily_report_time=_time("DAILY_REPORT_TIME", "08:00"),
        cve_scan_interval=_float("CVE_SCAN_INTERVAL", 6),
        cpu_threshold=_float("CPU_THRESHOLD", 90),
        mem_threshold=_float("MEM_THRESHOLD", 90),
        swap_threshold=_float("SWAP_THRESHOLD", 80),
        disk_threshold=_float("DISK_THRESHOLD", 85),
        inode_threshold=_float("INODE_THRESHOLD", 85),
        load_threshold=_float("LOAD_THRESHOLD", 2.0),
        docker_ignore=tuple(_list("DOCKER_IGNORE")),
        trivy_bin=_env("TRIVY_BIN", "trivy"),
        trivy_cache_dir=_env("TRIVY_CACHE_DIR", "/data/trivy-cache"),
        cve_severities=tuple(s.upper() for s in _list("CVE_SEVERITIES", "CRITICAL")),
        cve_ignore_unfixed=_bool("CVE_IGNORE_UNFIXED", True),
        cve_scan_host=_bool("CVE_SCAN_HOST", True),
        cve_scan_images=_bool("CVE_SCAN_IMAGES", True),
        cve_timeout=_int("CVE_TIMEOUT", 3600),
        kev_url=_env("KEV_URL", Config.kev_url),
        auto_stop_exploited=_bool("AUTO_STOP_EXPLOITED", False),
        auto_stop_exclude=tuple(_list("AUTO_STOP_EXCLUDE", "vanguarea-bot")),
        ssh_fail_threshold=_int("SSH_FAIL_THRESHOLD", 15),
        ssh_trusted_ips=tuple(_list("SSH_TRUSTED_IPS")),
        geoip_provider=(_env("GEOIP_PROVIDER", "ipinfo") or "ipinfo").lower(),
        ipinfo_token=_env("IPINFO_TOKEN", ""),
        syn_recv_threshold=_int("SYN_RECV_THRESHOLD", 200),
        conn_per_ip_threshold=_int("CONN_PER_IP_THRESHOLD", 150),
        rx_pps_threshold=_int("RX_PPS_THRESHOLD", 50_000),
        rx_mbps_threshold=_float("RX_MBPS_THRESHOLD", 500),
        access_logs=tuple(_list("ACCESS_LOGS")),
        http_rate_threshold=_int("HTTP_RATE_THRESHOLD", 600),
        http_scan_threshold=_int("HTTP_SCAN_THRESHOLD", 20),
        watched_files=tuple(_list("WATCHED_FILES", DEFAULT_WATCHED_FILES)),
    )
