from pathlib import Path

from vanguarea_bot.checks import docker_check
from vanguarea_bot.config import Config
from vanguarea_bot.state import State


def attrs(name, status="running", health=None, exit_code=0, oneoff=False, started="2026-10-23T08:00:00.123456789Z"):
    labels = {"com.docker.compose.project": "race-cycling-app", "com.docker.compose.service": "race-cycling-app"}
    if oneoff:
        labels["com.docker.compose.oneoff"] = "True"
    state = {"Status": status, "ExitCode": exit_code, "StartedAt": started}
    if health:
        state["Health"] = {"Status": health}
    return {"Name": "/" + name, "State": state, "RestartCount": 0, "Config": {"Image": "app:latest", "Labels": labels}}


def test_oneoff_containers_grouped_instead_of_one_alert_each(tmp_path: Path):
    cfg = Config(token="x", chat_ids=frozenset({1}), state_file=tmp_path / "s.json")
    containers = [docker_check.parse_container(attrs(f"race-cycling-app-race-cycling-app-run-{i:012x}",
                                                     health="unhealthy", oneoff=True)) for i in range(7)]
    containers.append(docker_check.parse_container(attrs("race-cycling-app-run-x", status="exited", exit_code=1,
                                                         oneoff=True)))
    containers.append(docker_check.parse_container(attrs("race-cycling-app-api-1", health="unhealthy")))
    now = docker_check._parse_time("2026-10-23T10:00:00Z")
    alerts = docker_check.oneoff_alerts(containers, now=now)
    assert len(alerts) == 1 and alerts[0].key == "docker:oneoff:race-cycling-app"
    assert "<b>7</b> encore actif(s)" in alerts[0].body and "<b>1</b> terminé(s) en erreur" in alerts[0].body
    keys = [a.key for a in docker_check.alerts(containers, cfg, State(cfg.state_file))]
    # Le vrai service reste surveillé individuellement, les tâches ponctuelles non.
    assert "docker:unhealthy:race-cycling-app-api-1" in keys
    assert not any("run-" in k for k in keys)


def test_recent_oneoff_task_is_not_reported():
    c = docker_check.parse_container(attrs("app-run-1", health="unhealthy", oneoff=True,
                                           started="2026-10-23T09:50:00Z"))
    assert docker_check.oneoff_alerts([c], now=docker_check._parse_time("2026-10-23T10:00:00Z")) == []
