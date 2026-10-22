import os
import time
from pathlib import Path

from vanguarea_bot.checks import cleanup
from vanguarea_bot.config import Config


def make(path: Path, size: int = 4096, age: float = 0) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x" * size)
    os.utime(path.parent, (time.time() - age, time.time() - age))
    return path


def fake_host(tmp_path: Path) -> Config:
    home = tmp_path / "home" / "ubuntu"
    # 3 versions de VS Code Server : la plus récente doit être gardée
    for i, commit in enumerate(["aaa", "bbb", "ccc"]):
        make(home / f".vscode-server/cli/servers/Stable-{commit}/server/node", age=(3 - i) * 86400)
    make(home / ".vscode-server/code-aaa", age=3 * 86400)
    make(home / ".vscode-server/code-ccc", age=0)
    # Extensions : deux versions de la même
    make(home / ".vscode-server/extensions/golang.go-0.40.0/package.json")
    make(home / ".vscode-server/extensions/golang.go-0.42.1/package.json")
    # Caches GoLand de deux versions + backend distant
    make(home / ".cache/JetBrains/GoLand2024.3/index/x")
    make(home / ".cache/JetBrains/GoLand2025.2/index/x")
    make(home / ".cache/JetBrains/RemoteDev/dist/111_GoLand-2024.3/bin/goland.sh", age=86400)
    make(home / ".cache/JetBrains/RemoteDev/dist/222_GoLand-2025.2/bin/goland.sh", age=0)
    make(home / ".cache/go-build/00/abc")
    make(home / "go/pkg/mod/github.com/x/y@v1/go.mod")
    make(tmp_path / "var/cache/apt/archives/openssl_3.deb")
    make(tmp_path / "var/log/syslog.2.gz")
    (tmp_path / "root").mkdir()
    return Config(token="x", chat_ids=frozenset({1}), host_root=tmp_path)


def test_editor_items_keep_newest_and_running(tmp_path, monkeypatch):
    monkeypatch.setattr(cleanup, "MIN_SIZE", 0)
    cfg = fake_host(tmp_path)
    # Stable-aaa (le plus ancien) est encore utilisé par un processus : il ne doit pas être proposé.
    running = "/home/ubuntu/.vscode-server/cli/servers/Stable-aaa/server/node --port 1234"
    items = cleanup.editor_items(cfg, running)
    text = "\n".join(c for i in items for c in i.cmds)
    assert "Stable-bbb" in text
    assert "Stable-aaa" not in text and "Stable-ccc" not in text
    assert "/home/ubuntu/.vscode-server/code-aaa" in text and "code-ccc" not in text
    assert "golang.go-0.40.0" in text and "golang.go-0.42.1" not in text
    assert "GoLand2024.3" in text and "GoLand2025.2" not in text
    assert "111_GoLand-2024.3" in text and "222_GoLand" not in text
    assert str(tmp_path) not in text  # chemins affichés tels que vus depuis l'hôte


def test_caches_and_format(tmp_path, monkeypatch):
    monkeypatch.setattr(cleanup, "MIN_SIZE", 0)
    cfg = fake_host(tmp_path)
    items = cleanup.cache_items(cfg) + cleanup.editor_items(cfg, "")
    cmds = "\n".join(c for i in items for c in i.cmds)
    assert "sudo rm -rf /home/ubuntu/.cache/go-build /home/ubuntu/go/pkg/mod" not in cmds  # titres séparés
    assert "/home/ubuntu/.cache/go-build" in cmds and "/home/ubuntu/go/pkg/mod" in cmds
    text = cleanup.format_cleanup(items)
    assert "Tout le nettoyage sans risque en une fois" in text
    assert "<pre>" not in text


def test_unsafe_items_are_not_in_all_in_one(tmp_path):
    items = [cleanup.Item("Cache", 10 ** 9, cmds=["sudo apt-get clean"]),
             cleanup.Item("Cache 2", 10 ** 9, cmds=["docker builder prune -a -f"]),
             cleanup.Item("Volumes", 10 ** 9, cmds=["docker volume rm db"], safe=False)]
    text = cleanup.format_cleanup(items)
    all_in_one = text.split("Tout le nettoyage sans risque en une fois")[1]
    assert "docker volume rm" not in all_in_one
    assert "À vérifier" in text
    assert cleanup.reclaimable(items) == (3 * 10 ** 9, 2 * 10 ** 9)
