# Vanguarea Bot 🛡

Bot Telegram qui surveille un VPS (OS, conteneurs Docker, CVE, attaques) et vous envoie des alertes et un rapport quotidien.

## Fonctionnalités

| Domaine | Ce qui est surveillé | Alerte automatique |
|---|---|---|
| **OS** | CPU, RAM, swap, charge, disques et inodes, uptime, services systemd en échec, redémarrage requis, mises à jour (apt/dnf) dont sécurité, processus zombies, comptes UID 0 suspects | ✅ (seuils configurables) |
| **Docker** | État de chaque conteneur, healthcheck, redémarrages, OOM kill, CPU/RAM | ✅ arrêt anormal, *unhealthy*, boucle de redémarrage, OOM |
| **CVE** | Paquets de l'hôte (OS + dépendances applicatives) et images Docker en cours d'exécution, via [Trivy](https://trivy.dev) | ✅ scan quotidien, seules les **nouvelles** CVE sont signalées, **avec le correctif à appliquer** |
| **SSH** | Échecs d'authentification par IP, brute force distribué, connexions réussies, échecs `sudo` | ✅ |
| **DDoS / flood** | SYN flood (connexions `SYN_RECV` + SYN cookies du noyau), trop de connexions depuis une IP, débit / paquets entrants anormaux | ✅ |
| **Web** | Logs d'accès nginx/Apache/Caddy/Traefik : flood HTTP par IP, scans de vulnérabilités (`/.env`, `wp-login.php`, `../`, Log4Shell, injections SQL…) | ✅ (si `ACCESS_LOGS` est renseigné) |
| **Intégrité** | `/etc/passwd`, `shadow`, `sudoers`, `authorized_keys`, `sshd_config`, cron, `ld.so.preload`… | ✅ toute modification, création de compte, ajout de clé SSH |
| **Ports** | Nouveaux ports ouverts sur l'extérieur (backdoor, service exposé par erreur) | ✅ |
| **fail2ban** | IP bannies par jail | dans `/security` et le rapport |

Les alertes « durables » (disque plein, conteneur arrêté…) sont répétées au plus une fois par heure (`ALERT_COOLDOWN`) et un message **✅ Résolu** est envoyé quand le problème disparaît.

### Commandes Telegram

| Commande | Description |
|---|---|
| `/status` | État de l'OS |
| `/docker` | Conteneurs (état, santé, CPU, RAM) |
| `/security` | Résumé sécurité depuis le dernier rapport (SSH, fail2ban, web) |
| `/network` | Trafic, connexions, top IP connectées |
| `/ports` | Ports en écoute et processus associés |
| `/updates` | Mises à jour disponibles (sécurité en premier) |
| `/cleanup` | Espace disque récupérable et commandes de nettoyage |
| `/cve` | Lance un scan complet des CVE maintenant |
| `/fix [projet]` | Correctifs exacts à appliquer pour les CVE du dernier scan |
| `/report` | Rapport complet |
| `/mute 60` / `/unmute` | Couper les alertes pendant une maintenance |

## Installation

### 1. Créer le bot Telegram

1. Sur Telegram, écrivez à **@BotFather** → `/newbot` → récupérez le **token**.
2. Récupérez votre **chat ID** : écrivez à **@userinfobot**, ou lancez le bot puis envoyez-lui `/start` (il répond avec votre ID même si vous n'êtes pas encore autorisé).

### 2. Déploiement avec Docker (recommandé)

```bash
git clone https://github.com/taumoutsh/vanguarea-bot.git /opt/vanguarea-bot
cd /opt/vanguarea-bot
cp .env.example .env
nano .env                 # TELEGRAM_BOT_TOKEN et TELEGRAM_CHAT_IDS au minimum
docker compose up -d --build
docker compose logs -f
```

Le conteneur a besoin d'un accès étendu à l'hôte pour le surveiller (voir `docker-compose.yml`) :
- `/` monté **en lecture seule** sur `/host` : logs, paquets, fichiers sensibles. Les commandes de l'hôte (`apt`, `systemctl`, `journalctl`, `fail2ban-client`) sont exécutées via `chroot /host`.
- `pid: host` et `network_mode: host` : processus, connexions et trafic réels de l'hôte.
- le socket Docker : état des conteneurs et scan des images.

> ⚠️ L'accès au socket Docker équivaut à un accès root sur la machine. Ne donnez le token du bot à personne et limitez `TELEGRAM_CHAT_IDS` à vos propres comptes. Le bot est **en lecture seule** : il ne propose aucune commande qui modifie le serveur.

Le premier scan CVE télécharge la base Trivy (~1 Go de cache dans `./data/trivy-cache`).

### 3. Alternative : installation directe sur l'hôte (systemd)

```bash
sudo git clone https://github.com/taumoutsh/vanguarea-bot.git /opt/vanguarea-bot
cd /opt/vanguarea-bot
sudo python3 -m venv .venv && sudo .venv/bin/pip install -r requirements.txt
sudo cp .env.example .env && sudo nano .env
# Installer Trivy : https://trivy.dev/latest/getting-started/installation/
sudo cp deploy/vanguarea-bot.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now vanguarea-bot
```

Le service doit tourner en **root** (lecture de `auth.log`, `/etc/shadow`, socket Docker…).

## Configuration

Toutes les options sont dans [`.env.example`](.env.example) avec leurs valeurs par défaut. Les plus utiles :

- `CVE_SEVERITIES=CRITICAL` (ou `CRITICAL,HIGH`) et `CVE_IGNORE_UNFIXED=true` pour ne remonter que ce que vous pouvez corriger.
- `ACCESS_LOGS=/var/log/nginx/access.log` pour activer la détection d'attaques web. Pour un reverse proxy en conteneur, activez ses logs d'accès dans un fichier monté sur l'hôte (Traefik : `accesslog.filePath`, format texte ou JSON).
- `SSH_TRUSTED_IPS` pour ne pas être notifié de vos propres connexions SSH.
- `DOCKER_IGNORE` pour les conteneurs ponctuels.

## Corriger les CVE

Le bot reste **en lecture seule** : il ne modifie jamais votre code ni vos conteneurs. Pour chaque faille, il vous envoie la marche à suivre :

- **Serveur** : la commande `apt`/`dnf`/`apk` qui met à jour uniquement les paquets vulnérables, et un rappel de redémarrer si le noyau est concerné.
- **Image construite par vos projets** (docker compose) : il retrouve le projet et son dossier grâce aux labels compose, puis indique :
  - les paquets système à corriger : reconstruction avec `--pull`, ou version du `FROM` à monter ;
  - les dépendances à mettre à jour : `npm install pkg@^x.y.z` (ou `overrides` pour les dépendances indirectes), lignes `requirements.txt`, `go get`, version de Go pour la stdlib ;
  - les commandes `git commit`/`git push` et `docker compose build`/`up -d` du service concerné.
- **Image tierce** (postgres, nginx…) : `docker compose pull` + `up -d`, ou monter le tag s'il est figé.

La version proposée est la plus petite version corrigée dans la même version majeure, pour limiter les risques de régression.

## Libérer de l'espace disque

`/cleanup` (également rappelé dans l'alerte « disque plein » et dans le rapport quotidien au-delà de 1 Go) liste ce qui peut être supprimé, avec la commande correspondante. Le bot ne supprime rien lui-même.

- **Sans risque** : anciennes versions de VS Code Server / CLI, Cursor, backends JetBrains (GoLand, IntelliJ…) et caches d'anciennes versions, anciennes versions d'extensions (la version la plus récente et celles en cours d'utilisation sont toujours conservées), caches Go / npm / pip / Yarn, images Docker inutilisées, cache de build Docker, cache apt, paquets apt orphelins, anciennes révisions snap, journaux systemd au-delà de 200 Mo.
- **À vérifier** (jamais inclus dans la commande « tout en une fois ») : conteneurs arrêtés, volumes Docker non utilisés (ils contiennent des données !), logs de conteneurs volumineux, anciens logs archivés.

## Ce que le bot peut et ne peut pas détecter

- **SSH brute force, scans web, nouveaux ports, modifications de comptes/clés** : détection fiable, c'est là que le bot apporte le plus.
- **DDoS** : le bot détecte un SYN flood, un flood de connexions depuis quelques IP, ou un pic de trafic sur l'interface. En revanche, un DDoS volumétrique sature votre lien **avant** d'atteindre le serveur : seule la protection de votre hébergeur (anti-DDoS OVH, Hetzner, Cloudflare…) peut l'absorber. Ajustez `RX_MBPS_THRESHOLD` à ~50-70 % du débit de votre offre.
- **Recommandé en complément** : `fail2ban` (bannissement automatique, le bot affiche son état), un pare-feu (`ufw`) et `unattended-upgrades` pour les mises à jour de sécurité. Le bot lit les listes de paquets de l'hôte : si `apt update` n'est jamais lancé (ce que fait `unattended-upgrades` ou le timer `apt-daily`), les mises à jour ne seront pas vues.

## Développement

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt pytest
.venv/bin/python -m pytest
```

Structure :

```
vanguarea_bot/
├── bot.py            # commandes Telegram + tâches planifiées
├── config.py         # variables d'environnement
├── state.py          # persistance, anti-spam des alertes
├── logtail.py        # lecture incrémentale des logs
└── checks/
    ├── system.py     # OS, ressources, mises à jour
    ├── docker_check.py
    ├── cve.py        # Trivy
    ├── ssh.py        # auth.log / journald, fail2ban
    ├── network.py    # SYN flood, connexions, trafic, ports
    ├── web.py        # logs d'accès HTTP
    └── integrity.py  # fichiers sensibles
```
