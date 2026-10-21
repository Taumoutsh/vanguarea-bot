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
    text = remedy.advise_host(result, running_kernel="6.1.0-18-amd64")
    assert "<code>sudo apt-get install --only-upgrade -y linux-image-amd64 openssl</code>" in text
    assert "<code>sudo apt-get update &amp;&amp; sudo apt-get install" in text  # tout en une ligne
    assert "sudo reboot" in text


def test_versioned_kernel_packages_use_metapackage():
    result = cve.TargetResult("hôte", [
        vuln("linux-image-6.8.0-45-generic", "6.8.0-45.45", "6.8.0-50.51", cls="os-pkgs", pkg_type="ubuntu"),
        vuln("linux-headers-6.8.0-45-generic", "6.8.0-45.45", "6.8.0-50.51", cls="os-pkgs", pkg_type="ubuntu",
             cve_id="C2"),
        vuln("linux-image-6.8.0-40-generic", "6.8.0-40.40", "6.8.0-50.51", cls="os-pkgs", pkg_type="ubuntu",
             cve_id="C3"),
    ])
    text = remedy.advise_host(result, running_kernel="6.8.0-45-generic")
    # On ne demande jamais de mettre à jour le paquet versionné déjà installé...
    assert "install --only-upgrade -y linux-headers-generic linux-image-generic</code>" in text
    assert "install --only-upgrade -y linux-image-6.8.0" not in text
    # ... et l'ancien noyau inutilisé est à supprimer.
    assert "autoremove --purge" in text
    assert "sudo reboot" in text


def test_third_party_go_binary_in_built_image(tmp_path: Path):
    # Cas réel : trivy copié depuis aquasec/trivy dans l'image du bot, sans go.mod dans le projet.
    (tmp_path / "Dockerfile").write_text("FROM python:3.12-slim\n")
    cfg = Config(token="x", chat_ids=frozenset({1}))
    ctx = ImageContext("bot:latest", "bot-1", "vanguarea-bot", "vanguarea-bot", str(tmp_path), built=True)
    vulns = [cve.Vuln(c, "CRITICAL", p, i, f, "", "", "lang-pkgs", "gobinary", "usr/local/bin/trivy")
             for c, p, i, f in [("C1", "github.com/aquasecurity/trivy", "v0.58.1", "0.71.1"),
                                ("C2", "golang.org/x/crypto", "v0.31.0", "0.55.0"),
                                ("C3", "stdlib", "v1.23.4", "1.26.10")]]
    text = remedy.advise(cfg, [cve.TargetResult("bot:latest", vulns)], {"bot:latest": [ctx]})[1]
    assert "Binaire tiers" in text and "/usr/local/bin/trivy" in text
    assert "≥ <b>0.71.1</b>" in text
    assert "go get" not in text


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


def test_own_go_project_single_go_get_and_roundtrip(tmp_path: Path):
    (tmp_path / "go.mod").write_text("module example.com/monapp\n\ngo 1.22\n")
    state = State(tmp_path / "s.json")
    vulns = [cve.Vuln(c, "CRITICAL", p, i, f, "", "", "lang-pkgs", "gobinary", "app/server")
             for c, p, i, f in [("C1", "example.com/monapp", "v0.0.0", ""),
                                ("C2", "golang.org/x/net", "v0.17.0", "0.23.0"),
                                ("C3", "golang.org/x/crypto", "v0.17.0", "0.31.0"),
                                ("C4", "stdlib", "v1.21.0", "1.21.8")]]
    cve.record_and_diff([cve.TargetResult("svc", vulns)], state)
    loaded = cve.last_results(State(tmp_path / "s.json"))
    ctx = ImageContext("svc", "svc-1", "monapp", "api", str(tmp_path), built=True)
    text = remedy.advise(Config(token="x", chat_ids=frozenset({1})), loaded, {"svc": [ctx]})[1]
    assert "<code>go get golang.org/x/crypto@v0.31.0 golang.org/x/net@v0.23.0</code>" in text
    assert "golang:1.21.8" in text


def test_requirements_commands_edit_file_in_place(tmp_path: Path):
    import subprocess

    req = tmp_path / "requirements.txt"
    req.write_text('Django==4.2.1\nurllib3[socks] ; python_version>="3.8"\npyyaml')
    cmds = remedy.requirements_commands(req.read_text(), {"django": "4.2.16", "urllib3": "2.2.2",
                                                          "jinja2": "3.1.4"}, str(req))
    assert all("\n" not in c for c in cmds)  # une ligne par commande : copiable d'un appui
    for cmd in cmds:
        subprocess.run(cmd, shell=True, check=True)
    assert req.read_text() == ('Django==4.2.16\nurllib3[socks]>=2.2.2 ; python_version>="3.8"\n'
                               "pyyaml\njinja2>=3.1.4\n")


def test_npm_overrides_as_single_line_command(tmp_path: Path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"express": "^4.17.0"}}))
    lines = remedy.npm_advice({"express": ("4.17.0", "4.20.0", ["C1"]), "qs": ("6.5.0", "6.5.3", ["C2"])}, tmp_path)
    text = "\n".join(lines)
    assert "<pre>" not in text
    assert "npm install express@^4.20.0" in text
    assert "node -e" in text and '{"qs": "^6.5.3"}' in text
