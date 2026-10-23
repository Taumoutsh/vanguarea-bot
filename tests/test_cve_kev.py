import json
import os
import time
from pathlib import Path

from vanguarea_bot.checks import cve, exploit_guard, kev
from vanguarea_bot.checks.docker_check import ImageContext
from vanguarea_bot.config import Config
from vanguarea_bot.state import State


def v(cve_id, pkg="openssl", severity="CRITICAL", exploited=False):
    return cve.Vuln(cve_id, severity, pkg, "1.0", "1.1", "titre", "https://x", "os-pkgs", "debian", "",
                    exploited)


def cfg_for(tmp_path, **kw):
    return Config(token="x", chat_ids=frozenset({1}), state_file=tmp_path / "state.json", **kw)


def test_reportable_keeps_configured_severity_and_all_exploited(tmp_path):
    cfg = cfg_for(tmp_path, cve_severities=("CRITICAL",))
    results = [cve.TargetResult("app", [v("C1"), v("C2", severity="HIGH"), v("C3", severity="MEDIUM")])]
    cve.mark_exploited(results, {"C3": {}})
    kept = cve.reportable(results, cfg)[0].vulns
    assert [x.cve for x in kept] == ["C1", "C3"]  # HIGH non exploitée filtrée, MEDIUM exploitée gardée
    assert kept[1].exploited


def test_report_diff_is_between_reports_not_scans(tmp_path):
    state = State(tmp_path / "s.json")
    assert cve.report_diff(state, update_baseline=True) == ([], 0, True)  # aucun scan : rien à faire
    cve.record([cve.TargetResult("app", [v("C1")])], state)
    assert cve.report_diff(state, update_baseline=True)[2] is True  # premier rapport : référence
    # Plusieurs scans entre deux rapports : C2 apparaît, C1 corrigée, C3 apparaît puis disparaît.
    cve.record([cve.TargetResult("app", [v("C1"), v("C2"), v("C3")])], state)
    cve.record([cve.TargetResult("app", [v("C2")])], state)
    new, fixed, first = cve.report_diff(state, update_baseline=False)  # /report : ne change pas la référence
    assert [x.cve for x in new[0].vulns] == ["C2"] and fixed == 1 and not first
    assert cve.report_diff(state, update_baseline=True)[0][0].vulns[0].cve == "C2"
    assert cve.report_diff(state, update_baseline=True) == ([], 0, False)  # rapport suivant : rien de neuf


def test_failed_scan_target_is_neither_new_nor_fixed(tmp_path):
    state = State(tmp_path / "s.json")
    cve.record([cve.TargetResult("app", [v("C1")])], state)
    cve.report_diff(state, update_baseline=True)
    cve.record([cve.TargetResult("app", error="timeout")], state)
    assert cve.report_diff(state, update_baseline=True) == ([], 0, False)
    cve.record([cve.TargetResult("app", [v("C1")])], state)
    assert cve.report_diff(state, update_baseline=True) == ([], 0, False)


def ctx(name, project="race", service="api"):
    return ImageContext("img:latest", name, project, service, "/home/ubuntu/projects/race", built=True)


def test_only_containers_with_exploited_cve_are_stopped(tmp_path):
    cfg = cfg_for(tmp_path, auto_stop_exploited=True)
    state = State(cfg.state_file)
    stopped = []
    results = [cve.TargetResult("img:latest", [v("C1", exploited=True)]),
               cve.TargetResult("other:latest", [v("C9")])]  # critique mais non exploitée
    contexts = {"img:latest": [ctx("race-api-1")], "other:latest": [ctx("other-1", "other", "web")]}
    alerts = exploit_guard.check(cfg, state, results, contexts, {"C1": {"vulnerabilityName": "RCE"}},
                                 stop=lambda c, n: stopped.append(n))
    assert stopped == ["race-api-1"]
    assert len(alerts) == 1 and "arrêté" in alerts[0].title and "docker compose up -d api" in alerts[0].body
    # Relancé à la main : pas de nouvel arrêt pour les mêmes CVE, mais toujours une alerte.
    alerts = exploit_guard.check(cfg, state, results, contexts, {}, stop=lambda c, n: stopped.append(n))
    assert stopped == ["race-api-1"] and "Relancé manuellement" in alerts[0].body
    # Nouvelle CVE exploitée : nouvel arrêt.
    results[0].vulns.append(v("C2", exploited=True))
    exploit_guard.check(cfg, state, results, contexts, {}, stop=lambda c, n: stopped.append(n))
    assert stopped == ["race-api-1", "race-api-1"]


def test_auto_stop_disabled_or_excluded_only_alerts(tmp_path):
    results = [cve.TargetResult("img:latest", [v("C1", exploited=True)])]
    contexts = {"img:latest": [ctx("npm-1", "proxy_manager", "npm")]}
    for cfg, reason in [(cfg_for(tmp_path), "désactivé"),
                        (cfg_for(tmp_path, auto_stop_exploited=True, auto_stop_exclude=("proxy_manager",)), "exclu")]:
        alerts = exploit_guard.check(cfg, State(cfg.state_file), results, contexts, {},
                                     stop=lambda c, n: (_ for _ in ()).throw(AssertionError("ne doit pas arrêter")))
        assert alerts[0].stateful and reason in alerts[0].body


def test_kev_cache_used_when_download_fails(tmp_path):
    cfg = cfg_for(tmp_path, kev_url="http://127.0.0.1:9/indisponible")
    cache = tmp_path / "kev.json"
    cache.write_text(json.dumps({"vulnerabilities": [{"cveID": "CVE-1", "vulnerabilityName": "x"}]}))
    old = time.time() - 2 * kev.REFRESH
    os.utime(cache, (old, old))
    assert set(kev.load(cfg)) == {"CVE-1"}
    assert kev.load(cfg_for(Path(tmp_path / "vide"), kev_url="http://127.0.0.1:9/x")) == {}
