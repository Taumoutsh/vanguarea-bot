"""Persistance de l'état (déduplication des alertes, positions dans les logs...)."""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

CRITICAL = "critical"
WARNING = "warning"
INFO = "info"

ICONS = {CRITICAL: "🚨", WARNING: "⚠️", INFO: "ℹ️"}


@dataclass
class Alert:
    """Une alerte produite par une vérification.

    ``stateful`` : l'alerte décrit une condition durable (disque plein, conteneur
    arrêté...). Elle est répétée au plus une fois par ``cooldown`` tant que la
    condition persiste, et un message « résolu » est envoyé quand elle disparaît.
    Sinon c'est un événement ponctuel (connexion SSH, nouveau port...).
    """

    key: str
    level: str
    title: str
    body: str = ""
    stateful: bool = True
    extra: dict = field(default_factory=dict)

    def render(self) -> str:
        text = f"{ICONS.get(self.level, '•')} <b>{self.title}</b>"
        if self.body:
            text += f"\n{self.body}"
        return text


class State:
    """Petit magasin clé/valeur persisté en JSON (thread-safe)."""

    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.RLock()
        self.data: dict = {}
        self._load()

    def _load(self) -> None:
        try:
            self.data = json.loads(self.path.read_text())
        except FileNotFoundError:
            self.data = {}
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("État illisible (%s), réinitialisation", exc)
            self.data = {}

    def save(self) -> None:
        with self.lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.data, indent=1, sort_keys=True))
            os.replace(tmp, self.path)

    def section(self, name: str) -> dict:
        with self.lock:
            return self.data.setdefault(name, {})

    # --- Statistiques journalières (remises à zéro après le rapport quotidien)
    def incr(self, counter: str, key: str, amount: int = 1) -> None:
        with self.lock:
            daily = self.data.setdefault("daily", {}).setdefault(counter, {})
            daily[key] = daily.get(key, 0) + amount

    def daily(self) -> dict:
        with self.lock:
            return json.loads(json.dumps(self.data.get("daily", {})))

    def reset_daily(self) -> None:
        with self.lock:
            self.data["daily"] = {}
            self.save()

    # --- Mode silencieux
    def muted_until(self) -> float:
        return float(self.data.get("muted_until", 0))

    def set_muted_until(self, ts: float) -> None:
        with self.lock:
            self.data["muted_until"] = ts
            self.save()


class AlertManager:
    """Décide quelles alertes envoyer (anti-spam + notifications de résolution)."""

    def __init__(self, state: State, cooldown: int):
        self.state = state
        self.cooldown = cooldown

    def process(self, group: str, alerts: list[Alert], now: float | None = None) -> list[str]:
        now = time.time() if now is None else now
        messages: list[str] = []
        with self.state.lock:
            active = self.state.data.setdefault("active_alerts", {}).setdefault(group, {})
            events = self.state.data.setdefault("events", {})
            current = {a.key for a in alerts if a.stateful}

            for alert in alerts:
                store = active if alert.stateful else events
                last = store.get(alert.key, {}).get("ts")
                if last is None or now - last >= self.cooldown:
                    messages.append(alert.render())
                    store[alert.key] = {"ts": now, "title": alert.title}
                    self.state.incr("alerts", alert.level)

            for key in list(active):
                if key not in current:
                    messages.append(f"✅ <b>Résolu</b> : {active[key]['title']}")
                    del active[key]

            for key in [k for k, v in events.items() if now - v["ts"] > 7 * 86400]:
                del events[key]

            self.state.save()

        if messages and now < self.state.muted_until():
            log.info("Mode silencieux : %d alerte(s) non envoyée(s)", len(messages))
            return []
        return messages
