"""Bot Telegram : commandes interactives et vérifications planifiées."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import asdict
from datetime import datetime
from zoneinfo import ZoneInfo

from telegram import BotCommand, LinkPreviewOptions, Update
from telegram.constants import ParseMode
from telegram.ext import Application, CommandHandler, ContextTypes, Defaults, filters

from . import __version__
from .checks import (cleanup, cve, docker_check, exploit_guard, integrity, kev, network, packages, registry, remedy,
                     ssh, system, web)
from .config import Config, load_config
from .state import WARNING, Alert, AlertManager, State
from .utils import chunk_message, copy_cmd, esc, human_bytes, human_duration

log = logging.getLogger("vanguarea")

COMMANDS = [
    ("status", "État de l'OS (CPU, RAM, disques, mises à jour)"),
    ("docker", "État des conteneurs Docker"),
    ("security", "Résumé sécurité (SSH, fail2ban, attaques)"),
    ("network", "Connexions et trafic réseau"),
    ("ports", "Ports en écoute"),
    ("updates", "Mises à jour disponibles"),
    ("cleanup", "Espace disque récupérable et commandes de nettoyage"),
    ("cve", "Lancer un scan des CVE (paquets + images)"),
    ("fix", "Correctifs à appliquer pour les CVE (ex : /fix monprojet)"),
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
            cfg = self.cfg
            results = await asyncio.to_thread(cve.scan_all, cfg)
            kev_db = await asyncio.to_thread(kev.load, cfg)
            cve.mark_exploited(results, kev_db)
            results = cve.reportable(results, cfg)
            await asyncio.to_thread(cve.record, results, self.state)
            try:
                contexts = await asyncio.to_thread(docker_check.image_contexts, cfg)
            except Exception:  # noqa: BLE001 - sans Docker, seules les CVE de l'hôte sont traitées
                log.exception("Contexte des images indisponible")
                contexts = {}
            # Les scans planifiés sont silencieux : seules les failles activement exploitées
            # déclenchent une alerte immédiate. Le reste est résumé dans le rapport quotidien.
            await asyncio.to_thread(self._check_image_updates, results, contexts)
            await asyncio.to_thread(self._check_packages, results)
            alerts = await asyncio.to_thread(exploit_guard.check, cfg, self.state, results, contexts, kev_db)
            await self.dispatch(app, "kev", alerts)
            if not scheduled:
                duration = human_duration(time.time() - started)
                await self.reply(update, cve.format_results(results, "Scan des CVE") + f"\n\n⏱ Durée : {duration}")

    def _check_image_updates(self, results: list[cve.TargetResult], contexts: dict) -> None:
        """Pour chaque image tierce vulnérable, cherche une version plus récente sur son registre."""
        updates: dict[str, dict] = {}
        for r in results:
            ctxs = contexts.get(r.target) or []
            if not r.vulns or not ctxs or ctxs[0].built:
                continue
            update = registry.check_image(self.cfg, r.target)
            if update:
                ctx = ctxs[0]
                services = " ".join(sorted({c.service for c in ctxs if c.service}))
                info = asdict(update)
                plan = remedy.third_party_plan(self.cfg, r.target, ctx, services, info)
                label = f"{ctx.project} / {services}" if ctx.project else ctx.container
                updates[r.target] = {**info, "label": label, "cves": len(r.vulns), "status": plan.status,
                                     "command": " && ".join(plan.cmds), "manual": plan.manual}
        with self.state.lock:
            self.state.section("cve")["image_updates"] = updates
            self.state.save()

    def _check_packages(self, results: list[cve.TargetResult]) -> None:
        """Version corrigée disponible dans les dépôts apt / publiée sur npm, PyPI, Go ?"""
        try:
            infos = packages.check(self.cfg, results)
        except Exception:  # noqa: BLE001 - information facultative
            log.exception("Vérification des versions de paquets impossible")
            return
        with self.state.lock:
            self.state.section("cve")["package_updates"] = infos
            self.state.save()

    def package_updates(self) -> dict[str, dict]:
        with self.state.lock:
            return dict(self.state.data.get("cve", {}).get("package_updates", {}))

    def image_updates(self) -> dict[str, dict]:
        with self.state.lock:
            return dict(self.state.data.get("cve", {}).get("image_updates", {}))

    async def fix_advice(self, results: list[cve.TargetResult], project: str | None = None) -> list[str]:
        try:
            contexts = await asyncio.to_thread(docker_check.image_contexts, self.cfg)
        except Exception:  # noqa: BLE001 - sans Docker, on donne quand même les correctifs de l'hôte
            log.exception("Contexte des images indisponible")
            contexts = {}
        return await asyncio.to_thread(remedy.advise, self.cfg, results, contexts, project, self.image_updates(),
                                       self.package_updates())

    async def job_daily_report(self, context: ContextTypes.DEFAULT_TYPE) -> None:
        text = await self.build_report(update_baseline=True)
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
                exploited = info.get("exploited", 0)
                icon = "🔥" if exploited else "🔴" if info["count"] else "✅"
                extra = f" (dont <b>{exploited} exploitée(s)</b>)" if exploited else ""
                lines.append(f"• {icon} {esc(target)} : {info['count']}{extra}")
        return "\n".join(lines)

    def cve_report(self, update_baseline: bool) -> str:
        """Résumé du dernier scan + CVE apparues ou corrigées depuis le rapport quotidien précédent."""
        lines = [self.cve_summary()]
        updates = sorted(self.image_updates().values(), key=lambda u: u["label"])
        if updates:
            lines += ["", "🐳 <b>Images tierces vulnérables</b>"]
            for u in updates:
                status = u.get("status")
                head = f"• <b>{esc(u['label'])}</b> ({esc(u['tag'])}) — {u['cves']} CVE"
                if status == "newer":
                    target = u.get("newer_minor") or u.get("newer_major")
                    major = "" if u.get("newer_minor") else " (version majeure : lisez les notes de version)"
                    lines.append(f"{head}\n  ⬆️ Version <b>{esc(target)}</b> disponible{major}")
                elif status == "tag_updated":
                    lines.append(f"{head}\n  ⬆️ Nouvelle image publiée pour ce tag")
                elif status == "none":
                    lines.append(f"{head}\n  ⏳ Aucune version plus récente publiée : rien à faire pour l'instant")
                    continue
                else:
                    reason = f" ({esc(u['error'])})" if u.get("error") else ""
                    lines.append(f"{head}\n  ❔ Version plus récente non vérifiable{reason} : essayez une mise à jour")
                if u.get("manual"):
                    old, new = u["manual"].split(" → ")
                    lines.append(f"  Remplacez <code>{esc(old)}</code> par <code>{esc(new)}</code> dans le "
                                 "docker-compose.yml, puis :")
                if u.get("command"):
                    lines.append("  " + copy_cmd(u["command"]))
            lines.append("<i>Détails : /fix</i>")
        pkgs = self.package_updates().values()
        apt_ready = sum(1 for p in pkgs if p["ecosystem"] == "apt" and p.get("available"))
        apt_waiting = [p["name"] for p in pkgs if p["ecosystem"] == "apt" and p.get("available") is False]
        lang_waiting = [p["name"] for p in pkgs if p["ecosystem"] != "apt" and p.get("available") is False]
        if apt_ready or apt_waiting or lang_waiting:
            lines += ["", "📦 <b>Correctifs des paquets</b>"]
            if apt_ready:
                lines.append(f"• Serveur : <b>{apt_ready}</b> paquet(s) corrigeable(s) maintenant avec apt (/fix serveur)")
            if apt_waiting:
                lines.append(f"• Serveur : ⏳ {len(apt_waiting)} correctif(s) pas encore dans vos dépôts "
                             f"({esc(', '.join(sorted(apt_waiting)[:5]))}{' …' if len(apt_waiting) > 5 else ''})")
            if lang_waiting:
                lines.append(f"• Dépendances : ⏳ {len(lang_waiting)} version(s) corrigée(s) pas encore publiée(s) "
                             f"({esc(', '.join(sorted(lang_waiting)[:5]))}{' …' if len(lang_waiting) > 5 else ''})")
        new, fixed, first = cve.report_diff(self.state, update_baseline)
        if first:
            lines.append("<i>Première référence établie : les nouvelles CVE seront signalées "
                         "à partir du prochain rapport.</i>")
            return "\n".join(lines)
        if fixed:
            lines.append(f"✅ <b>{fixed}</b> CVE corrigée(s) ou disparue(s) depuis le dernier rapport")
        if new:
            lines += ["", cve.format_results(new, "🆕 Nouvelles CVE depuis le dernier rapport", max_per_target=5)]
        else:
            lines.append("🆕 Aucune nouvelle CVE depuis le dernier rapport")
        return "\n".join(lines)

    async def build_report(self, update_baseline: bool = False) -> str:
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
        items = await asyncio.to_thread(cleanup.collect, cfg)
        total, safe = cleanup.reclaimable(items)
        if safe >= 1024 ** 3:
            parts.append(f"🧹 <b>{human_bytes(safe)}</b> récupérables sans risque "
                         f"({human_bytes(total)} au total) : /cleanup")
        parts.append(await asyncio.to_thread(self.security_summary))
        parts.append(self.cve_report(update_baseline))
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

    async def cmd_cleanup(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await self.reply(update, "🔎 Analyse de l'espace disque…")
        items = await asyncio.to_thread(cleanup.collect, self.cfg)
        await self.reply(update, cleanup.format_cleanup(items))

    async def cmd_fix(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        results = cve.last_results(self.state)
        if not results:
            await self.reply(update, "Aucun scan disponible : lancez d'abord /cve.")
            return
        project = context.args[0] if context.args else None
        for block in await self.fix_advice(results, project):
            await self.reply(update, block)

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
        stop = "activé" if self.cfg.auto_stop_exploited else "désactivé (AUTO_STOP_EXPLOITED)"
        await self.broadcast(app, f"🤖 <b>Vanguarea démarré</b> v{__version__}\n"
                                  f"Surveillance active. Trivy : {trivy}\n"
                                  f"Scan CVE toutes les {self.cfg.cve_scan_interval:g} h, "
                                  f"arrêt auto des failles exploitées : {stop}\n/help pour les commandes.")

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
            "ports": self.cmd_ports, "updates": self.cmd_updates, "cve": self.cmd_cve, "fix": self.cmd_fix,
            "cleanup": self.cmd_cleanup,
            "report": self.cmd_report, "mute": self.cmd_mute, "unmute": self.cmd_unmute,
        }
        for name, callback in handlers.items():
            app.add_handler(CommandHandler(name, callback, filters=allowed, block=False))
        app.add_handler(CommandHandler(["start", "help"], self.cmd_unauthorized, filters=~allowed))

        jq = app.job_queue
        jq.run_repeating(self.job_system, interval=cfg.check_interval, first=15, name="system")
        jq.run_repeating(self.job_security, interval=cfg.security_interval, first=10, name="security")
        jq.run_repeating(self.job_cve, interval=cfg.cve_scan_interval * 3600, first=300, name="cve")
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
