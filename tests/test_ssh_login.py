from pathlib import Path

from vanguarea_bot.checks import geoip, ssh
from vanguarea_bot.config import Config
from vanguarea_bot.state import CRITICAL, INFO, WARNING, State

GITHUB_KEY = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
GITHUB_FP = "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU"  # empreinte publiée par GitHub


def fake_host(tmp_path: Path) -> Config:
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/passwd").write_text("ubuntu:x:1000:1000::/home/ubuntu:/bin/bash\n")
    ssh_dir = tmp_path / "home/ubuntu/.ssh"
    ssh_dir.mkdir(parents=True)
    (ssh_dir / "authorized_keys").write_text(f'no-pty ssh-ed25519 {GITHUB_KEY} sinan@macbook\n')
    return Config(token="x", chat_ids=frozenset({1}), host_root=tmp_path, state_file=tmp_path / "s.json")


def geo(monkeypatch, table):
    monkeypatch.setattr(geoip, "lookup", lambda cfg, state, ip: table.get(ip, {}))


def test_fingerprint_matches_openssh():
    assert ssh.fingerprint(GITHUB_KEY) == GITHUB_FP


def test_accept_line_parses_key_fingerprint():
    line = f"sshd-session[1]: Accepted publickey for ubuntu from 203.0.113.10 port 5 ssh2: ED25519 {GITHUB_FP}"
    login = ssh.parse_lines([line]).logins[0]
    assert (login.user, login.ip, login.key_type, login.fingerprint) == ("ubuntu", "203.0.113.10", "ED25519",
                                                                         GITHUB_FP)


def test_known_key_known_ip_then_new_country(tmp_path, monkeypatch):
    cfg = fake_host(tmp_path)
    state = State(cfg.state_file)
    geo(monkeypatch, {"203.0.113.10": {"country": "FR", "city": "Lyon", "org": "Free SAS"},
                      "198.51.100.7": {"country": "RU", "org": "Hosting Ltd"}})
    first = ssh.login_alert(cfg, state, ssh.Login("ubuntu", "203.0.113.10", "publickey", "ED25519", GITHUB_FP),
                            now=1000)
    assert first.level == INFO and "🔑 <b>sinan@macbook</b>" in first.body and "🇫🇷 FR, Lyon · Free SAS" in first.body
    again = ssh.login_alert(cfg, state, ssh.Login("ubuntu", "203.0.113.10", "publickey", "ED25519", GITHUB_FP),
                            now=1000 + 2 * 86400)
    assert "IP connue (dernière connexion il y a 2j" in again.body
    russia = ssh.login_alert(cfg, state, ssh.Login("ubuntu", "198.51.100.7", "publickey", "ED25519", "SHA256:autre"),
                             now=5000 + 2 * 86400)
    assert russia.level == CRITICAL and "pays jamais vu" in russia.title and "clé inconnue" in russia.body


def test_password_login_and_trusted_ip(tmp_path, monkeypatch):
    cfg = fake_host(tmp_path)
    geo(monkeypatch, {})
    alert = ssh.login_alert(cfg, State(cfg.state_file), ssh.Login("ubuntu", "203.0.113.10", "password"))
    assert alert.level == WARNING and "mot de passe" in alert.body
    trusted = Config(token="x", chat_ids=frozenset({1}), host_root=tmp_path, state_file=tmp_path / "t.json",
                     ssh_trusted_ips=("203.0.113.10",))
    assert ssh.login_alert(trusted, State(trusted.state_file), ssh.Login("ubuntu", "203.0.113.10", "publickey")) is None


def test_geoip_local_and_describe(tmp_path):
    cfg = Config(token="x", chat_ids=frozenset({1}), state_file=tmp_path / "s.json")
    assert geoip.lookup(cfg, State(cfg.state_file), "192.168.1.5") == {"local": True}
    assert geoip.flag("FR") == "🇫🇷" and geoip.flag(None) == ""
    text = geoip.describe("8.8.8.8", {"country": "US", "city": "Mountain View", "org": "Google LLC",
                                      "hostname": "dns.google"})
    assert text == "<code>8.8.8.8</code> — 🇺🇸 US, Mountain View · Google LLC · <code>dns.google</code>"
