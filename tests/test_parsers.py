import json
from pathlib import Path

from vanguarea_bot.checks import cve, network, ssh, web
from vanguarea_bot.config import Config
from vanguarea_bot.logtail import read_new_lines
from vanguarea_bot.state import CRITICAL, WARNING, Alert, AlertManager, State
from vanguarea_bot.utils import chunk_message


def make_cfg(tmp_path: Path, **kw) -> Config:
    return Config(token="x", chat_ids=frozenset({1}), state_file=tmp_path / "state.json", **kw)


def test_decode_addr_ipv4_and_ipv6():
    assert network.decode_addr("0100007F:0050") == ("127.0.0.1", 80)
    assert network.decode_addr("00000000000000000000000001000000:01BB") == ("::1", 443)
    # ::ffff:192.168.1.10 vu en IPv6
    assert network.decode_addr("0000000000000000FFFF00000A01A8C0:0016") == ("192.168.1.10", 22)


def test_parse_proc_net_and_stats():
    content = (
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1\n"
        "   1: 0A01A8C0:0016 08080808:D431 01 00000000:00000000 00:00000000 00000000     0        0 1002 1\n"
        "   2: 0A01A8C0:01BB 08080808:D432 03 00000000:00000000 00:00000000 00000000     0        0 1003 1\n"
    )
    sockets = network.parse_proc_net(content, "tcp")
    assert [s.state for s in sockets] == ["LISTEN", "ESTABLISHED", "SYN_RECV"]
    stats = network.connection_stats(sockets)
    assert stats.established_by_ip["8.8.8.8"] == 1
    assert stats.syn_recv_by_ip["8.8.8.8"] == 1
    assert network.listening_ports(sockets) == {("tcp", "0.0.0.0", 22)}


def test_ssh_parse_lines():
    lines = [
        "Oct 21 10:00:01 vps sshd[1]: Failed password for root from 1.2.3.4 port 5555 ssh2",
        "Oct 21 10:00:02 vps sshd[1]: Invalid user admin from 1.2.3.4 port 5556",
        "Oct 21 10:00:03 vps sshd[1]: Failed password for invalid user admin from 5.6.7.8 port 1 ssh2",
        "2026-10-21T10:00:04+0200 vps sshd-session[2]: Accepted publickey for sinan from 9.9.9.9 port 22 ssh2: ED25519",
        "Oct 21 10:00:05 vps sudo[3]:    bob : 3 incorrect password attempts ; TTY=pts/0 ; COMMAND=/bin/ls",
    ]
    ev = ssh.parse_lines(lines)
    assert ev.failures == {"1.2.3.4": 2, "5.6.7.8": 1}
    assert ev.logins == [ssh.Login("sinan", "9.9.9.9", "publickey")]
    assert ev.sudo_failures == {"bob": 1}


def test_ssh_bruteforce_alert(tmp_path, monkeypatch):
    cfg = make_cfg(tmp_path, ssh_fail_threshold=3, geoip_provider="none")
    state = State(cfg.state_file)
    lines = [f"sshd[1]: Failed password for root from 1.2.3.4 port {i} ssh2" for i in range(5)]
    monkeypatch.setattr(ssh, "read_auth_lines", lambda c, s: lines)
    alerts = ssh.check(cfg, state)
    assert [a.key for a in alerts] == ["ssh:bruteforce:1.2.3.4"]
    assert state.daily()["ssh_failed"] == {"1.2.3.4": 5}


def test_web_parse_combined_and_traefik():
    line = '203.0.113.5 - - [21/Oct/2026:10:00:00 +0200] "GET /.env HTTP/1.1" 404 153 "-" "curl"'
    req = web.parse_line(line)
    assert (req.ip, req.path, req.status) == ("203.0.113.5", "/.env", 404)
    traefik = json.dumps({"ClientHost": "203.0.113.6", "RequestPath": "/wp-login.php", "DownstreamStatus": 404})
    assert web.parse_line(traefik).ip == "203.0.113.6"
    ev = web.analyse([line, traefik, '1.1.1.1 - - [x] "GET / HTTP/1.1" 200 1 "-" "-"'])
    assert ev.suspicious == {"203.0.113.5": 1, "203.0.113.6": 1}
    assert ev.requests["1.1.1.1"] == 1


def test_trivy_parse_and_diff(tmp_path):
    raw = json.dumps({"Results": [{"Target": "debian", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2024-0001", "PkgName": "openssl", "InstalledVersion": "3.0.1",
         "FixedVersion": "3.0.2", "Severity": "CRITICAL", "Title": "boom"},
    ]}]})
    vulns = cve.parse_trivy_json(raw)
    assert vulns[0].cve == "CVE-2024-0001" and vulns[0].fixed == "3.0.2"
    state = State(tmp_path / "s.json")
    results = [cve.TargetResult("hôte", vulns)]
    cve.record(results, state)
    assert cve.last_results(state)[0].vulns[0].cve == "CVE-2024-0001"
    assert "openssl" in cve.format_results(results, "Scan")


def test_alert_manager_cooldown_and_resolution(tmp_path):
    state = State(tmp_path / "s.json")
    mgr = AlertManager(state, cooldown=100)
    disk = Alert("sys:disk:/", CRITICAL, "Disque plein")
    assert len(mgr.process("system", [disk], now=1000)) == 1
    assert mgr.process("system", [disk], now=1050) == []  # cooldown
    assert len(mgr.process("system", [disk], now=1101)) == 1  # rappel
    resolved = mgr.process("system", [], now=1200)
    assert resolved and "Résolu" in resolved[0]
    event = Alert("ssh:login:x", WARNING, "Login", stateful=False)
    assert len(mgr.process("ssh", [event], now=1000)) == 1
    assert mgr.process("ssh", [], now=1001) == []  # pas de « résolu » pour un événement


def test_logtail_incremental_and_rotation(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("old line\n")
    pos: dict = {}
    assert read_new_lines(log, pos) == []  # premier passage : fin du fichier
    with log.open("a") as fh:
        fh.write("new 1\nnew 2\npartial")
    assert read_new_lines(log, pos) == ["new 1", "new 2"]
    log.unlink()
    log.write_text("rotated\n")
    assert read_new_lines(log, pos) == ["rotated"]


def test_chunk_message():
    text = "\n".join("x" * 100 for _ in range(100))
    chunks = chunk_message(text, limit=1000)
    assert all(len(c) <= 1000 for c in chunks)
    assert "\n".join(chunks) == text
