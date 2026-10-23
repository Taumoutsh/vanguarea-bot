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
    # ... et l'ancien noyau est supprimé explicitement (autoremove garde le noyau précédent).
    assert "<code>sudo apt-get purge -y linux-image-6.8.0-40-generic</code>" in text
    assert "sudo reboot" in text


def test_old_kernel_leftovers_without_flavor_are_purged():
    # Cas réel : noyau 6.14.0-15 resté installé, le serveur tourne sur 6.14.0-37.
    pkgs = ["linux-headers-6.14.0-15", "linux-headers-6.14.0-15-generic", "linux-modules-6.14.0-15-generic",
            "linux-tools-6.14.0-15", "linux-tools-6.14.0-15-generic"]
    result = cve.TargetResult("hôte", [vuln(p, "6.14.0-15.15", "6.14.0-37.37", cls="os-pkgs", pkg_type="ubuntu",
                                            cve_id=f"C{i}") for i, p in enumerate(pkgs)])
    text = remedy.advise_host(result, running_kernel="6.14.0-37-generic")
    assert "--only-upgrade" not in text  # rien à « mettre à jour » : tout est à supprimer
    assert "sudo apt-get purge -y " + " ".join(pkgs) in text
    assert "sudo reboot" not in text


def test_newer_installed_kernel_needs_reboot_not_purge():
    result = cve.TargetResult("hôte", [vuln("linux-tools-6.14.0-37-generic", "6.14.0-37.37", "6.14.0-40.40",
                                            cls="os-pkgs", pkg_type="ubuntu")])
    text = remedy.advise_host(result, running_kernel="6.14.0-15-generic")
    assert "purge" not in text
    assert "prochain redémarrage" in text and "sudo reboot" in text


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
    cve.record([cve.TargetResult("svc", vulns)], state)
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


def _assert_balanced_html(text: str):
    from html.parser import HTMLParser

    class Checker(HTMLParser):
        def __init__(self):
            super().__init__()
            self.stack = []

        def handle_starttag(self, tag, attrs):
            self.stack.append(tag)

        def handle_endtag(self, tag):
            assert self.stack and self.stack.pop() == tag, f"balise </{tag}> mal fermée"

    checker = Checker()
    checker.feed(text)
    assert checker.stack == [], f"balises non fermées : {checker.stack}"


def test_third_party_image_readable_and_tag_aware():
    cfg = Config(token="x", chat_ids=frozenset({1}))
    ctx = ImageContext("jc21/nginx-proxy-manager:latest", "npm-1", "proxy_manager", "npm",
                       "/home/ubuntu/proxy_manager", built=False)
    result = cve.TargetResult(ctx.ref, [vuln("libexpat", "2.8.5-r0", "2.9.0-r0", cls="os-pkgs", pkg_type="alpine")])
    text = remedy.advise(cfg, [result], {ctx.ref: [ctx]})[1]
    _assert_balanced_html(text)
    assert "CVE-2026" not in text  # évite les faux liens « numéro de téléphone » de Telegram
    assert "pas encore publié" in text and "figée" not in text
    # une seule commande visible, le détail est replié
    assert text.count("<blockquote expandable>") == 1
    assert "<code>cd /home/ubuntu/proxy_manager &amp;&amp; docker compose pull npm" in text
    assert remedy._tag("postgres:16") == "16" and remedy._tag("sha256:abc") is None


def test_chunk_message_never_splits_blockquote():
    from vanguarea_bot.utils import chunk_message, copy_steps

    block = "\n".join(copy_steps([f"commande-{i} " + "x" * 50 for i in range(10)]))
    text = "\n".join([block] * 20)
    chunks = chunk_message(text, limit=1500)
    assert len(chunks) > 1
    for chunk in chunks:
        assert chunk.count("<blockquote") == chunk.count("</blockquote>")
        _assert_balanced_html(chunk)


def test_host_dependencies_grouped_by_origin(tmp_path):
    base = "home/ubuntu/.vscode-server/data/agent-host/sdk-cache/claude/0.3.220/linux-x64/node_modules"
    vulns = [cve.Vuln(f"CVE-{i}", "CRITICAL", "fast-uri", "3.1.2", "2.4.3, 3.1.4, 4.1.1", "", "", "lang-pkgs",
                      "node-pkg", f"{base}/fast-uri/package.json") for i in range(12)]
    vulns.append(cve.Vuln("CVE-X", "CRITICAL", "requests", "2.0.0", "2.32.0", "", "", "lang-pkgs", "python-pkg",
                          "opt/app/venv/lib/python3.12/site-packages/requests-2.0.0.dist-info/METADATA"))
    text = remedy.advise_host(cve.TargetResult("hôte", vulns), running_kernel="x")
    _assert_balanced_html(text)
    # Une seule entrée pour l'extension VS Code, pas une ligne par CVE
    assert text.count("fast-uri") == 1
    assert "VS Code Server" in text and "<code>~/.vscode-server</code>" in text and "/cleanup" in text
    assert "<code>/opt/app/venv/bin/pip install &#x27;requests&gt;=2.32.0&#x27;</code>" in text or \
        "/opt/app/venv/bin/pip install 'requests&gt;=2.32.0'" in text


def test_system_binaries_mapped_to_their_package():
    def vuln_in(path, pkg):
        return cve.Vuln("CVE-1", "CRITICAL", pkg, "v0.26.3", "0.28.1", "", "", "lang-pkgs", "gobinary", path)

    vulns = [vuln_in("usr/libexec/docker/cli-plugins/docker-compose", "github.com/moby/buildkit"),
             vuln_in("usr/libexec/docker/cli-plugins/docker-buildx", "github.com/moby/spdystream"),
             vuln_in("usr/local/bin/outil-maison", "golang.org/x/net")]
    owners = {"/usr/libexec/docker/cli-plugins/docker-compose": ("apt", "docker-compose-plugin"),
              "/usr/libexec/docker/cli-plugins/docker-buildx": ("apt", "docker-buildx-plugin")}
    text = remedy.advise_host(cve.TargetResult("hôte", vulns), running_kernel="x", owner_of=owners.get)
    _assert_balanced_html(text)
    assert "sudo apt-get install --only-upgrade -y docker-buildx-plugin docker-compose-plugin</code>" in text
    assert "hors gestionnaire de paquets" in text and "outil-maison" in text


def test_package_owner_parses_dpkg(monkeypatch):
    from vanguarea_bot.utils import CmdResult

    monkeypatch.setattr(remedy, "run_host_cmd", lambda cfg, args, timeout=0: CmdResult(
        0, "libssl3t64:amd64: /usr/lib/x86_64-linux-gnu/libssl.so.3\n", "") if args[0] == "dpkg-query"
        else CmdResult(1, "", ""))
    assert remedy.package_owner(Config(token="x", chat_ids=frozenset({1})), "/usr/lib/x") == ("apt", "libssl3t64")
