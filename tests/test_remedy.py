import json
from pathlib import Path

from vanguarea_bot.checks import cve, remedy
from vanguarea_bot.checks.docker_check import ImageContext
from vanguarea_bot.config import Config
from vanguarea_bot.state import State


def vuln(pkg, installed, fixed, cls="lang-pkgs", pkg_type="npm", cve_id="CVE-2026-0001"):
    return cve.Vuln(cve_id, "CRITICAL", pkg, installed, fixed, "", "", cls, pkg_type, "app/package-lock.json")


def test_pick_fixed_version_prefers_same_major():
    assert remedy.pick_fixed_version("1.2.0", "2.0.1, 1.2.5") == "1.2.5"
    assert remedy.pick_fixed_version("3.0.0", "2.0.1, 1.2.5") == "1.2.5"  # rien de plus récent : le plus petit
    assert remedy.pick_fixed_version("0.9", "") is None


def test_host_apt_advice_and_kernel_reboot():
    result = cve.TargetResult("hôte", [
        vuln("openssl", "3.0.1", "3.0.2", cls="os-pkgs", pkg_type="debian"),
        vuln("linux-image-amd64", "6.1.1", "6.1.2", cls="os-pkgs", pkg_type="debian", cve_id="CVE-2"),
    ])
    text = remedy.advise(Config(token="x", chat_ids=frozenset({1})), [result], {})[1]
    assert "apt-get install --only-upgrade linux-image-amd64 openssl" in text
    assert "redémarrage" in text


def test_built_image_npm_direct_and_indirect(tmp_path: Path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"express": "^4.17.0"}}))
    cfg = Config(token="x", chat_ids=frozenset({1}))
    ctx = ImageContext("monapi-api", "monapi-api-1", "monapi", "api", str(tmp_path), built=True)
    result = cve.TargetResult("monapi-api", [vuln("express", "4.17.0", "4.20.0"), vuln("qs", "6.5.0", "6.5.3")])
    blocks = remedy.advise(cfg, [result], {"monapi-api": [ctx]}, project="monapi")
    text = blocks[1]
    assert "npm install express@^4.20.0" in text
    assert '"qs": "^6.5.3"' in text
    assert "docker compose build --pull api" in text
    assert "git commit" in text


def test_third_party_image_pull(tmp_path: Path):
    cfg = Config(token="x", chat_ids=frozenset({1}))
    ctx = ImageContext("postgres:16", "db-1", "monapi", "db", "/opt/monapi", built=False)
    result = cve.TargetResult("postgres:16", [vuln("libpq", "16.1", "16.2", cls="os-pkgs", pkg_type="debian")])
    text = remedy.advise(cfg, [result], {"postgres:16": [ctx]})[1]
    assert "docker compose pull db" in text
    assert remedy.advise(cfg, [result], {"postgres:16": [ctx]}, project="autre")[0].startswith("✅")


def test_go_stdlib_and_last_results_roundtrip(tmp_path: Path):
    state = State(tmp_path / "s.json")
    result = cve.TargetResult("svc", [vuln("stdlib", "1.21.0", "1.21.8", pkg_type="gobinary"),
                                      vuln("golang.org/x/net", "0.17.0", "0.23.0", pkg_type="gobinary", cve_id="C2")])
    cve.record_and_diff([result], state)
    loaded = cve.last_results(State(tmp_path / "s.json"))
    text = remedy.advise(Config(token="x", chat_ids=frozenset({1})), loaded, {})[1]
    assert "go get golang.org/x/net@v0.23.0" in text
    assert "golang:1.21.8" in text
