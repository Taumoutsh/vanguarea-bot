"""Bot Telegram : commandes interactives et vérifications planifiées."""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime
from zoneinfo import ZoneInfo

from telegram import BotCommand, LinkPreviewOptions, Update
from telegram.constants import ParseMode
from telegram.ext import Application, CommandHandler, ContextTypes, Defaults, filters

from . import __version__
from .checks import cve, docker_check, integrity, network, ssh, system, web
from .config import Config, load_config
from .state import WARNING, Alert, AlertManager, State
from .utils import chunk_message, esc, human_duration

log = logging.getLogger("vanguarea")

COMMANDS = [
    ("status", "État de l'OS (CPU, RAM, disques, mises à jour)"),
    ("docker", "État des conteneurs Docker"),
    ("security", "Résumé sécurité (SSH, fail2ban, attaques)"),
    ("network", "Connexions et trafic réseau"),
    ("ports", "Ports en écoute"),
    ("updates", "Mises à jour disponibles"),
    ("cve", "Lancer un scan des CVE (paquets + images)"),
    ("report", "Rapport complet"),
    ("mute", "Couper les alertes (ex : /mute 60)"),
    ("unmute", "Réactiver les alertes"),
    ("help", "Aide"),
]


class Monitor:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.state = State(cfg.state_file)
        self.alerts = AlertManager(self.state, cfg.alert_cooldown)
        self.cve_lock = asyncio.Lock()
        self._updates: tuple[list[str] | None, list[str]] = (None, [])
        self._updates_checked = 0.0

    # ------------------------------------------------------------------ envoi
    async def broadcast(self, app: Application, text: str) -> None:
        for chat_id in self.cfg.chat_ids:
            for part in chunk_message(text):
                try:
                    await app.bot.send_message(chat_id, part)
                except Exception:  # noqa: BLE001 - on ne veut jamais faire tomber une tâche
                    log.exception("Envoi impossible vers %s", chat_id)

    async def reply(self, update: Update, text: str) -> None:
        for part in chunk_message(text):
            await update.effective_message.reply_text(part)

    async def dispatch(self, app: Application, group: str, alerts: list[Alert]) -> None:
        messages = self.alerts.process(group, alerts)
        if messages:
            header = f"🖥 <b>{esc(self.cfg.server_name)}</b>\n" if self.cfg.server_name else ""
            await self.broadcast(app, header + "\n\n".join(messages))

    # ------------------------------------------------------------- vérifications
    async def run_check(self, app: Application, group: str, func) -> None:
        try:
            alerts = await asyncio.to_thread(func)
        except Exception as exc:  # noqa: BLE001
            log.exception("Vérification %s en erreur", group)
            alerts = [Alert(f"{group}:error", WARNING, f"Vérification « {group} » impossible", esc(exc))]
        await self.dispatch(app, group, alerts)

    async def job_system(self, context: ContextTypes.DEFAULT_TYPE) -> None:
        await self.run_check(context.application, "system", self._system_alerts)
        await self.run_check(context.application, "docker",
                             lambda: docker_check.alerts(docker_check.collect(self.cfg), self.cfg, self.state))

    def _system_alerts(self) -> list[Alert]:
        status = system.collect(self.cfg, with_updates=False)
        # apt-get -s est coûteux : on rafraîchit la liste des mises à jour au plus toutes les 6 h.
        if time.time() - self._updates_checked >= 6 * 3600:
            self._updates = system.pending_updates(self.cfg)
            self._updates_checked = time.time()
        status.updates, status.security_updates = self._updates
        return system.alerts(status, self.cfg)

    async def job_security(self, context: ContextTypes.DEFAULT_TYPE) -> None:
        cfg, st = self.cfg, self.state
        app = context.application
        await self.run_check(app, "ssh", lambda: ssh.check(cfg, st))
        await self.run_check(app, "network", lambda: network.check(cfg, st))
        await self.run_check(app, "web", lambda: web.check(cfg, st))
        await self.run_check(app, "integrity", lambda: integrity.check(cfg, st))

    async def job_cve(self, context: ContextTypes.DEFAULT_TYPE) -> None:
        await self.scan_cve(context.application, scheduled=True)

    async def scan_cve(self, app: Application, scheduled: bool, update: Update | None = None) -> None:
        if not cve.trivy_available(self.cfg):
            msg = "❌ Trivy n'est pas installé : scan des CVE impossible."
            await (self.reply(update, msg) if update else self.broadcast(app, msg))
            return
        if self.cve_lock.locked():
            if update:
                await self.reply(update, "⏳ Un scan est déjà en cours.")
            return
        async with self.cve_lock:
            started = time.time()
            results = await asyncio.to_thread(cve.scan_all, self.cfg)
            new = await asyncio.to_thread(cve.record_and_diff, results, self.state)
            duration = human_duration(time.time() - started)
            errors = [r for r in results if r.error]
            if scheduled:
                # Planifié : on ne remonte que les nouvelles CVE (et les erreurs).
                if new or errors:
                    await self.broadcast(app, cve.format_results(new + errors, "Nouvelles CVE détectées"))
            else:
                text = cve.format_results(results, "Scan des CVE") + f"\n\n⏱ Durée : {duration}"
                await self.reply(update, text)

    async def job_daily_report(self, context: ContextTypes.DEFAULT_TYPE) -> None:
        text = await self.build_report()
        await self.broadcast(context.application, text)
        self.state.reset_daily()

    # ---------------------------------------------------------------- rapports
    def security_summary(self) -> str:
        daily = self.state.daily()
        lines = ["🔐 <b>Sécurité</b> (depuis le dernier rapport)"]
        ssh_failed = daily.get("ssh_failed", {})
        total = sum(ssh_failed.values())
        lines.append(f"• Échecs SSH : <b>{total}</b> depuis {len(ssh_failed)} IP")
        for ip, n in sorted(ssh_failed.items(), key=lambda kv: -kv[1])[:5]:
            lines.append(f"    <code>{esc(ip)}</code> : {n}")
        logins = daily.get("ssh_logins", {})
        if logins:
            lines.append("• Connexions SSH réussies : " + esc(", ".join(f"{k} ×{v}" for k, v in logins.items())))
        http = daily.get("http_suspicious", {})
        if self.cfg.access_logs:
            lines.append(f"• Requêtes HTTP suspectes : {sum(http.values())} depuis {len(http)} IP")
        alerts = daily.get("alerts", {})
        if alerts:
            lines.append(f"• Alertes émises : {alerts.get('critical', 0)} critiques, "
                         f"{alerts.get('warning', 0)} avertissements, {alerts.get('info', 0)} infos")
        f2b = ssh.fail2ban_status(self.cfg)
        if f2b is None:
            lines.append("• fail2ban : non détecté ⚠️ (recommandé)")
        else:
            for jail, (current, total_banned) in f2b.items():
                lines.append(f"• fail2ban <code>{esc(jail)}</code> : {current} IP bannies ({total_banned} au total)")
        return "\n".join(lines)

    def cve_summary(self) -> str:
        cve_state = self.state.data.get("cve", {})
        last = cve_state.get("last_scan")
        if not last:
            return "🛡 <b>CVE</b> : aucun scan effectué (/cve)"
        when = datetime.fromtimestamp(last, ZoneInfo(self.cfg.timezone)).strftime("%d/%m %H:%M")
        lines = [f"🛡 <b>CVE</b> (scan du {when}, sévérité {esc(','.join(self.cfg.cve_severities))})"]
        for target, info in cve_state.get("last_summary", {}).items():
            if info.get("error"):
                lines.append(f"• {esc(target)} : ❌ erreur")
            else:
                icon = "🔴" if info["count"] else "✅"
                lines.append(f"• {icon} {esc(target)} : {info['count']}")
        return "\n".join(lines)

    async def build_report(self) -> str:
        cfg = self.cfg
        sys_status = await asyncio.to_thread(system.collect, cfg)
        parts = [f"📋 <b>Rapport quotidien</b> — {datetime.now(ZoneInfo(cfg.timezone)).strftime('%d/%m/%Y %H:%M')}",
                 system.format_status(sys_status, cfg)]
        try:
            containers = await asyncio.to_thread(docker_check.collect, cfg)
            problems = [c for c in containers if (c.status != "running" and c.exit_code != 0) or c.health == "unhealthy"]
            running = sum(c.status == "running" for c in containers)
            line = f"🐳 <b>Docker</b> : {running}/{len(containers)} conteneur(s) actif(s)"
            if problems:
                line += "\n" + "\n".join(f"  ⚠️ {esc(c.name)} ({c.health or c.status})" for c in problems)
            parts.append(line)
        except Exception as exc:  # noqa: BLE001
            parts.append(f"🐳 Docker : indisponible ({esc(exc)})")
        parts.append(await asyncio.to_thread(self.security_summary))
        parts.append(self.cve_summary())
        return "\n\n".join(parts)

    # --------------------------------------------------------------- commandes
    async def cmd_help(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        lines = [f"🤖 <b>Vanguarea</b> v{__version__} — surveillance du serveur", ""]
        lines += [f"/{name} — {esc(desc)}" for name, desc in COMMANDS]
        lines += ["", f"Votre chat ID : <code>{update.effective_chat.id}</code>"]
        await self.reply(update, "\n".join(lines))

    async def cmd_status(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        status = await asyncio.to_thread(system.collect, self.cfg, False)
        if self._updates_checked:
            status.updates, status.security_updates = self._updates
        await self.reply(update, system.format_status(status, self.cfg).replace(
            "📦 Mises à jour : non vérifiables", "📦 Mises à jour : voir /updates"))

    async def cmd_updates(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await self.reply(update, "⏳ Vérification des mises à jour…")
        updates, security = await asyncio.to_thread(system.pending_updates, self.cfg)
        if updates is None:
            text = "❌ Impossible de vérifier les mises à jour (apt/dnf introuvable)."
        elif not updates:
            text = "📦 Le système est à jour ✅"
        else:
            text = f"📦 <b>{len(updates)} paquet(s) à mettre à jour</b>, dont {len(security)} de sécurité\n"
            if security:
                text += "\n🔐 <b>Sécurité</b> : " + esc(", ".join(security))
            others = [u for u in updates if u not in security]
            if others:
                text += "\n\n📦 Autres : " + esc(", ".join(others[:60]))
                if len(others) > 60:
                    text += f" … (+{len(others) - 60})"
            text += "\n\n💡 <code>sudo apt update &amp;&amp; sudo apt upgrade</code>"
        await self.reply(update, text)

    async def cmd_docker(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        try:
            containers = await asyncio.to_thread(docker_check.collect, self.cfg, True)
            await self.reply(update, docker_check.format_containers(containers))
        except Exception as exc:  # noqa: BLE001
            await self.reply(update, f"❌ Docker indisponible : <code>{esc(exc)}</code>")

    async def cmd_security(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await self.reply(update, await asyncio.to_thread(self.security_summary))

    async def cmd_network(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await self.reply(update, await asyncio.to_thread(network.format_network, self.cfg))

    async def cmd_ports(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await self.reply(update, await asyncio.to_thread(network.format_ports))

    async def cmd_cve(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await self.reply(update, "🔎 Scan des CVE lancé, cela peut prendre plusieurs minutes…")
        await self.scan_cve(context.application, scheduled=False, update=update)

    async def cmd_report(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await self.reply(update, await self.build_report())

    async def cmd_mute(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        minutes = int(context.args[0]) if context.args and context.args[0].isdigit() else 60
        self.state.set_muted_until(time.time() + minutes * 60)
        await self.reply(update, f"🔕 Alertes coupées pendant {minutes} min (/unmute pour réactiver).")

    async def cmd_unmute(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        self.state.set_muted_until(0)
        await self.reply(update, "🔔 Alertes réactivées.")

    # ------------------------------------------------------------- démarrage
    async def on_startup(self, app: Application) -> None:
        await app.bot.set_my_commands([BotCommand(n, d) for n, d in COMMANDS])
        trivy = "✅" if cve.trivy_available(self.cfg) else "❌ (scan CVE désactivé)"
        await self.broadcast(app, f"🤖 <b>Vanguarea démarré</b> v{__version__}\n"
                                  f"Surveillance active. Trivy : {trivy}\n/help pour les commandes.")

    def build_app(self) -> Application:
        cfg = self.cfg
        tz = ZoneInfo(cfg.timezone)
        defaults = Defaults(parse_mode=ParseMode.HTML, tzinfo=tz,
                            link_preview_options=LinkPreviewOptions(is_disabled=True))
        app = Application.builder().token(cfg.token).defaults(defaults).post_init(self.on_startup).build()

        allowed = filters.Chat(chat_id=list(cfg.chat_ids))
        handlers = {
            "start": self.cmd_help, "help": self.cmd_help, "status": self.cmd_status,
            "docker": self.cmd_docker, "security": self.cmd_security, "network": self.cmd_network,
            "ports": self.cmd_ports, "updates": self.cmd_updates, "cve": self.cmd_cve,
            "report": self.cmd_report, "mute": self.cmd_mute, "unmute": self.cmd_unmute,
        }
        for name, callback in handlers.items():
            app.add_handler(CommandHandler(name, callback, filters=allowed, block=False))
        app.add_handler(CommandHandler(["start", "help"], self.cmd_unauthorized, filters=~allowed))

        jq = app.job_queue
        jq.run_repeating(self.job_system, interval=cfg.check_interval, first=15, name="system")
        jq.run_repeating(self.job_security, interval=cfg.security_interval, first=10, name="security")
        jq.run_daily(self.job_cve, time=cfg.cve_scan_time.replace(tzinfo=tz), name="cve")
        jq.run_daily(self.job_daily_report, time=cfg.daily_report_time.replace(tzinfo=tz), name="report")
        return app

    async def cmd_unauthorized(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        log.warning("Accès refusé pour le chat %s (%s)", update.effective_chat.id,
                    update.effective_user.username if update.effective_user else "?")
        await update.effective_message.reply_text(
            f"⛔ Accès refusé. Ajoutez <code>{update.effective_chat.id}</code> à TELEGRAM_CHAT_IDS.")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    cfg = load_config()
    monitor = Monitor(cfg)
    log.info("Démarrage de Vanguarea (HOST_ROOT=%s)", cfg.host_root)
    monitor.build_app().run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)
