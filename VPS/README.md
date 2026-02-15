# Installation VPS Hetzner pour OpenClaw

> **[English version below](#english-version)**

---

## Qu'est-ce que ce script ?

`install.sh` installe OpenClaw **nativement** sur un VPS Hetzner (Ubuntu/Debian) avec une sécurité optimale. Le gateway OpenClaw tourne directement sur le serveur en tant que service systemd. Docker est utilisé uniquement pour les environnements sandbox isolés et le moteur de recherche privé SearXNG.

### Architecture déployée

```
VPS Hetzner
├── OpenClaw Gateway (natif, systemd)     ← Port 18789 (loopback)
├── Caddy reverse proxy (natif, systemd)  ← Port 80/443 (public)
├── Git Versioning (inotify watcher)      ← Auto-commit config & mémoire
├── Docker Engine                          ← Sandboxes uniquement
│   ├── Conteneurs sandbox (openclaw.managed=true)
│   └── SearXNG (port 8080 loopback)
└── Sécurité (CrowdSec, fail2ban, UFW, sysctl, AIDE, auditd)
```

---

## Prérequis

| Élément | Minimum | Recommandé |
|---------|---------|------------|
| OS | Ubuntu 22.04/24.04 ou Debian 12 | Ubuntu 24.04 |
| RAM | 2 Go | 4 Go+ |
| Disque | 15 Go libres | 20 Go+ SSD |
| Accès | Root via SSH avec clé | Clé Ed25519 |
| Réseau | Connectivité internet | IP publique fixe |

**Optionnel :**
- Un nom de domaine pointant vers l'IP du VPS (enregistrement DNS A)
- Une adresse email pour les certificats Let's Encrypt
- Des clés API pour les fournisseurs d'IA (OpenAI, Anthropic, etc.)

---

## Démarrage rapide

### 1. Se connecter au VPS

```bash
ssh root@VOTRE_IP_VPS
```

### 2. Télécharger le script

```bash
git clone https://github.com/akristou-omnilog/openclaw-coolify.git /tmp/openclaw-installer
```

### 3. Lancer l'installation

**Mode interactif (recommandé pour la première installation) :**

```bash
bash /tmp/openclaw-installer/VPS/install.sh
```

Le script vous guide étape par étape : nom d'utilisateur, port SSH, domaine, clés API.

**Mode automatique (sans prompts) :**

```bash
bash /tmp/openclaw-installer/VPS/install.sh \
  --non-interactive \
  --domain mon-domaine.com \
  --email moi@example.com \
  --ssh-port 2222
```

**Prévisualisation (aucune modification) :**

```bash
bash /tmp/openclaw-installer/VPS/install.sh --dry-run
```

---

## Options de la ligne de commande

| Option | Description | Valeur par défaut |
|--------|-------------|-------------------|
| `--domain <domaine>` | Nom de domaine pour HTTPS automatique | aucun (mode IP) |
| `--email <email>` | Email pour Let's Encrypt | requis si domaine |
| `--ssh-port <port>` | Port SSH personnalisé | 22 |
| `--user <nom>` | Utilisateur système à créer | openclaw |
| `--swap-size <taille>` | Taille du fichier swap | 2G |
| `--non-interactive` | Exécution sans prompts | désactivé |
| `--skip-hardening` | Ignorer le hardening SSH | désactivé |
| `--dry-run` | Afficher les actions sans les exécuter | désactivé |
| `--help` | Afficher l'aide | - |

---

## Phases d'installation

Le script exécute 5 phases séquentielles. Chaque fonction est **idempotente** : le script peut être relancé sans risque après une interruption.

### Phase 1 : Préparation système et sécurité

- Mise à jour de tous les paquets
- Création de l'utilisateur dédié avec copie des clés SSH
- Configuration du swap (2 Go)
- Hardening SSH (clé uniquement, root désactivé, tentatives limitées)
- Firewall UFW (politique deny in + deny out, seuls SSH/80/443 autorisés)
- CrowdSec (détection d'intrusion collaborative avec intelligence communautaire)
- fail2ban (ban SSH 24h après 3 tentatives)
- Hardening kernel via sysctl (anti-spoofing, SYN flood, ICMP, ptrace, eBPF)
- AIDE (surveillance d'intégrité des fichiers, vérification quotidienne à 5h)
- auditd (journalisation des accès à passwd, sudo, Docker socket)
- Mises à jour de sécurité automatiques

### Phase 2 : Docker (sandboxes uniquement)

- Installation de Docker Engine avec configuration sécurisée
- Lancement de SearXNG (moteur de recherche privé, loopback uniquement)
- Téléchargement des images sandbox (Python + Playwright)

### Phase 3 : OpenClaw natif

- Installation de Node.js 22, Bun, Go, Cloudflared, GitHub CLI
- Installation d'OpenClaw via npm
- Génération de la configuration et du token d'accès
- Saisie interactive des clés API (optionnel)
- Création du service systemd avec directives de sécurité

### Phase 4 : Reverse proxy Caddy

- Installation de Caddy
- Configuration HTTPS automatique (si domaine fourni) ou HTTP
- Headers de sécurité (HSTS, X-Frame-Options, CSP)
- Rate limiting via UFW

### Phase 5 : Post-installation

- Sauvegarde quotidienne automatique (2h, rétention 7 jours)
- **Git versioning** pour configuration et mémoire (auto-commit sur /new, /reset)
- **Service watcher** pour commits automatiques sur modification de fichiers
- Scripts de rollback (`~/git-rollback.sh`) et statut (`~/git-memory-status.sh`)
- Nettoyage Docker hebdomadaire
- Script de vérification de sécurité
- Rotation des logs
- Vérification de tous les services

---

## Après l'installation

### Accéder à OpenClaw

L'URL et le token sont affichés à la fin de l'installation et sauvegardés dans :

```bash
cat /home/openclaw/install-summary.txt
```

Ouvrez l'URL dans votre navigateur :
```
https://votre-domaine.com/?token=VOTRE_TOKEN
```

Ou via tunnel SSH (si pas de domaine) :
```bash
ssh -N -L 18789:127.0.0.1:18789 openclaw@VOTRE_IP -p VOTRE_PORT_SSH
# Puis ouvrir : http://localhost:18789/?token=VOTRE_TOKEN
```

### Premières étapes

1. Ouvrir l'URL du dashboard
2. Approuver l'appairage initial :
   ```bash
   sudo -u openclaw openclaw-approve
   ```
3. Lancer l'assistant de configuration :
   ```bash
   sudo -u openclaw openclaw onboard
   ```
4. Configurer les canaux (Telegram, WhatsApp, Discord) depuis le dashboard

### Modifier les clés API

```bash
sudo nano /home/openclaw/.openclaw/env
sudo systemctl restart openclaw-gateway
```

### Ajouter un domaine ultérieurement

1. Configurer un enregistrement DNS A pointant vers l'IP du VPS
2. Modifier le Caddyfile :
   ```bash
   sudo nano /etc/caddy/Caddyfile
   ```
   Remplacer `:80` par votre domaine :
   ```
   mon-domaine.com {
       reverse_proxy localhost:18789
       encode gzip
       header {
           Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
           X-Content-Type-Options "nosniff"
           X-Frame-Options "SAMEORIGIN"
           -Server
       }
   }
   ```
3. Redémarrer Caddy :
   ```bash
   sudo systemctl restart caddy
   ```
   Caddy obtient automatiquement un certificat Let's Encrypt.

---

## Commandes utiles

| Action | Commande |
|--------|----------|
| Statut du gateway | `systemctl status openclaw-gateway` |
| Logs du gateway | `journalctl -u openclaw-gateway -f` |
| Redémarrer le gateway | `sudo systemctl restart openclaw-gateway` |
| Rapport de sécurité | `sudo /home/openclaw/security-check.sh` |
| Alertes CrowdSec | `sudo cscli alerts list` |
| IPs bannies | `sudo cscli decisions list` |
| Statut fail2ban | `sudo fail2ban-client status sshd` |
| Lancer un backup | `/home/openclaw/backup.sh` |
| Voir les sandboxes | `docker ps --filter label=openclaw.managed=true` |
| Statut SearXNG | `docker ps --filter name=searxng` |
| Logs Caddy | `sudo journalctl -u caddy -f` |
| Vérifier AIDE | `sudo aide --check` |

---

## Git Versioning (Configuration & Mémoire)

Le script installe un système de versioning Git pour la configuration et la mémoire d'OpenClaw, permettant de revenir à une version stable en cas d'erreur.

### Répertoires versionnés

| Répertoire | Contenu | Exclusions |
|------------|---------|------------|
| `~/.openclaw/` | Configuration (openclaw.json) | credentials/, env, sessions/*.jsonl |
| `~/.openclaw/workspace/` | Mémoire (MEMORY.md, SOUL.md, memory/) | node_modules/, .cache/ |

### Commits automatiques

- **Hook `git-memory-commit`** : commit automatique sur `/new` et `/reset`
- **Service `openclaw-git-watcher`** : commit automatique sur modification de fichiers (debounce 30s)

### Commandes Git

| Action | Commande |
|--------|----------|
| Statut Git | `~/git-memory-status.sh` |
| Rollback interactif | `~/git-rollback.sh` |
| Lister commits config | `~/git-rollback.sh --list config` |
| Lister commits mémoire | `~/git-rollback.sh --list workspace` |
| Rollback config | `~/git-rollback.sh --rollback <hash> config` |
| Rollback mémoire | `~/git-rollback.sh --rollback <hash> workspace` |
| Voir diff | `~/git-rollback.sh --diff <hash> workspace` |
| Logs watcher | `journalctl -u openclaw-git-watcher -f` |

### Structure multi-agent

```
~/.openclaw/workspace/
└── memory/
    ├── agents/         # Mémoire privée par agent
    │   └── main/
    ├── shared/         # Mémoire partagée
    │   ├── project/    # Architecture, roadmap
    │   ├── users/      # Profils utilisateurs
    │   ├── decisions/  # Décisions collectives
    │   └── events/     # Événements inter-agents
    └── archive/        # Anciennes mémoires
```

### Guide complet

Voir `~/.openclaw/workspace/GIT_MEMORY.md` pour le guide détaillé de gestion multi-agent.

---

## Sécurité

### 14 couches de protection

| Couche | Outil | Fonction |
|--------|-------|----------|
| Périmètre cloud | Hetzner Firewall (manuel) | Filtrage au niveau réseau du datacenter |
| Périmètre hôte | UFW (deny in + deny out) | Filtrage strict entrant et sortant |
| Anti brute-force | fail2ban | Ban 24h après 3 tentatives SSH |
| IPS collaboratif | CrowdSec + bouncer iptables | Détection comportementale + IPs communautaires |
| Réseau kernel | sysctl hardening | Anti-spoofing, SYN flood, ICMP, paquets martiens |
| Authentification | SSH clé uniquement | Mot de passe désactivé, root désactivé |
| Intégrité fichiers | AIDE | Détecte modifications non-autorisées (rootkits) |
| Audit système | auditd | Journal des accès critiques |
| Applicatif | Caddy headers | HSTS, CSP, X-Frame-Options |
| Isolation processus | systemd hardening | NoNewPrivileges, ProtectSystem, PrivateTmp |
| Conteneurs | Docker no-new-privileges | Empêche l'escalade de privilèges dans les sandbox |
| Secrets | chmod 600 | Fichiers .env et config verrouillés |
| Metadata | UFW deny out 169.254.169.254 | Bloque l'accès aux métadonnées Hetzner |
| Patches | unattended-upgrades | Mises à jour de sécurité automatiques |

### Recommandation Hetzner

Activez également le **firewall cloud Hetzner** depuis la console (console.hetzner.cloud) avec les mêmes règles (SSH + 80 + 443) pour une défense en profondeur.

---

## Dépannage

### Le gateway ne démarre pas

```bash
# Voir les logs détaillés
journalctl -u openclaw-gateway -n 50 --no-pager

# Vérifier la configuration
cat /home/openclaw/.openclaw/openclaw.json | jq .

# Vérifier les variables d'environnement
cat /home/openclaw/.openclaw/env

# Redémarrer manuellement
sudo systemctl restart openclaw-gateway
```

### Impossible de se connecter en SSH après le hardening

Le script désactive l'authentification par mot de passe et le login root. Assurez-vous d'avoir :
1. Votre clé SSH dans `/home/openclaw/.ssh/authorized_keys`
2. Le bon port SSH (par défaut ou celui choisi lors de l'installation)

```bash
ssh openclaw@VOTRE_IP -p VOTRE_PORT -i ~/.ssh/votre_cle
```

Si vous êtes bloqué, utilisez la console Hetzner (accès VNC) pour réparer.

### SearXNG ne démarre pas

```bash
# Voir les logs du conteneur
docker logs searxng

# Redémarrer
docker restart searxng

# Recréer si nécessaire
docker rm -f searxng
# Relancer la partie SearXNG du script d'installation
```

### CrowdSec bloque une IP légitime

```bash
# Lister les décisions actives
sudo cscli decisions list

# Débloquer une IP
sudo cscli decisions delete --ip X.X.X.X
```

### Relancer l'installation après une erreur

Le script est idempotent. Relancez-le simplement :

```bash
bash /chemin/vers/install.sh
```

Chaque étape vérifie si elle a déjà été exécutée et saute automatiquement si c'est le cas.

---

## Fichiers importants

| Fichier | Description |
|---------|-------------|
| `/home/openclaw/.openclaw/openclaw.json` | Configuration du gateway OpenClaw |
| `/home/openclaw/.openclaw/env` | Variables d'environnement (clés API) |
| `/home/openclaw/.openclaw/workspace/` | Espace de travail des agents |
| `/home/openclaw/.openclaw/workspace/GIT_MEMORY.md` | Guide Git multi-agent |
| `/home/openclaw/.openclaw/credentials/` | Credentials des canaux |
| `/home/openclaw/backup.sh` | Script de sauvegarde |
| `/home/openclaw/security-check.sh` | Vérification de sécurité |
| `/home/openclaw/git-rollback.sh` | Rollback Git (config/mémoire) |
| `/home/openclaw/git-memory-status.sh` | Statut Git des repos |
| `/home/openclaw/git-auto-commit.sh` | Script du watcher Git |
| `/home/openclaw/install-summary.txt` | Résumé de l'installation (token) |
| `/etc/caddy/Caddyfile` | Configuration du reverse proxy |
| `/etc/systemd/system/openclaw-gateway.service` | Service systemd du gateway |
| `/etc/systemd/system/openclaw-git-watcher.service` | Service watcher Git |
| `/etc/sysctl.d/99-openclaw-hardening.conf` | Hardening kernel |
| `/etc/ssh/sshd_config.d/99-openclaw-hardening.conf` | Hardening SSH |
| `/etc/fail2ban/jail.local` | Configuration fail2ban |
| `/var/log/openclaw-install.log` | Log d'installation |
| `/var/log/openclaw-backup.log` | Log des sauvegardes |
| `/var/log/aide-check.log` | Rapport d'intégrité AIDE |

---
---

<a id="english-version"></a>

# Hetzner VPS Installation for OpenClaw

## What is this script?

`install.sh` installs OpenClaw **natively** on a Hetzner VPS (Ubuntu/Debian) with optimal security. The OpenClaw gateway runs directly on the server as a systemd service. Docker is used only for isolated sandbox environments and the private SearXNG search engine.

### Deployed Architecture

```
Hetzner VPS
├── OpenClaw Gateway (native, systemd)    ← Port 18789 (loopback)
├── Caddy reverse proxy (native, systemd) ← Port 80/443 (public)
├── Git Versioning (inotify watcher)      ← Auto-commit config & memory
├── Docker Engine                          ← Sandboxes only
│   ├── Sandbox containers (openclaw.managed=true)
│   └── SearXNG (port 8080 loopback)
└── Security (CrowdSec, fail2ban, UFW, sysctl, AIDE, auditd)
```

---

## Requirements

| Item | Minimum | Recommended |
|------|---------|-------------|
| OS | Ubuntu 22.04/24.04 or Debian 12 | Ubuntu 24.04 |
| RAM | 2 GB | 4 GB+ |
| Disk | 15 GB free | 20 GB+ SSD |
| Access | Root via SSH with key | Ed25519 key |
| Network | Internet connectivity | Static public IP |

**Optional:**
- A domain name pointing to the VPS IP (DNS A record)
- An email address for Let's Encrypt certificates
- API keys for AI providers (OpenAI, Anthropic, etc.)

---

## Quick Start

### 1. Connect to the VPS

```bash
ssh root@YOUR_VPS_IP
```

### 2. Download the script

```bash
git clone https://github.com/akristou-omnilog/openclaw-coolify.git /tmp/openclaw-installer
```

### 3. Run the installation

**Interactive mode (recommended for first install):**

```bash
bash /tmp/openclaw-installer/VPS/install.sh
```

The script guides you step by step: username, SSH port, domain, API keys.

**Automatic mode (no prompts):**

```bash
bash /tmp/openclaw-installer/VPS/install.sh \
  --non-interactive \
  --domain my-domain.com \
  --email me@example.com \
  --ssh-port 2222
```

**Preview mode (no changes made):**

```bash
bash /tmp/openclaw-installer/VPS/install.sh --dry-run
```

---

## Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--domain <domain>` | Domain name for automatic HTTPS | none (IP mode) |
| `--email <email>` | Email for Let's Encrypt | required if domain set |
| `--ssh-port <port>` | Custom SSH port | 22 |
| `--user <name>` | System user to create | openclaw |
| `--swap-size <size>` | Swap file size | 2G |
| `--non-interactive` | Run without prompts | off |
| `--skip-hardening` | Skip SSH hardening | off |
| `--dry-run` | Show actions without executing | off |
| `--help` | Show help | - |

---

## Installation Phases

The script runs 5 sequential phases. Every function is **idempotent**: the script can safely be re-run after an interruption.

### Phase 1: System Preparation & Security

- Full system update
- Dedicated user creation with SSH key copy
- Swap configuration (2 GB)
- SSH hardening (key-only, root disabled, limited attempts)
- UFW firewall (deny in + deny out policy, only SSH/80/443 allowed)
- CrowdSec (collaborative intrusion detection with community intelligence)
- fail2ban (SSH ban 24h after 3 attempts)
- Kernel hardening via sysctl (anti-spoofing, SYN flood, ICMP, ptrace, eBPF)
- AIDE (file integrity monitoring, daily check at 5 AM)
- auditd (logging access to passwd, sudo, Docker socket)
- Automatic security updates

### Phase 2: Docker (Sandboxes Only)

- Docker Engine installation with secure configuration
- SearXNG launch (private search engine, loopback only)
- Sandbox image download (Python + Playwright)

### Phase 3: Native OpenClaw

- Node.js 22, Bun, Go, Cloudflared, GitHub CLI installation
- OpenClaw installation via npm
- Configuration and access token generation
- Interactive API key input (optional)
- Systemd service creation with security directives

### Phase 4: Caddy Reverse Proxy

- Caddy installation
- Automatic HTTPS configuration (if domain provided) or HTTP
- Security headers (HSTS, X-Frame-Options, CSP)
- Rate limiting via UFW

### Phase 5: Post-Installation

- Automatic daily backup (2 AM, 7-day retention)
- **Git versioning** for configuration and memory (auto-commit on /new, /reset)
- **File watcher service** for automatic commits on file changes
- Rollback scripts (`~/git-rollback.sh`) and status (`~/git-memory-status.sh`)
- Weekly Docker cleanup
- Security check script
- Log rotation
- Full service verification

---

## After Installation

### Accessing OpenClaw

The URL and token are displayed at the end of installation and saved in:

```bash
cat /home/openclaw/install-summary.txt
```

Open the URL in your browser:
```
https://your-domain.com/?token=YOUR_TOKEN
```

Or via SSH tunnel (if no domain):
```bash
ssh -N -L 18789:127.0.0.1:18789 openclaw@YOUR_IP -p YOUR_SSH_PORT
# Then open: http://localhost:18789/?token=YOUR_TOKEN
```

### First Steps

1. Open the dashboard URL
2. Approve the initial pairing:
   ```bash
   sudo -u openclaw openclaw-approve
   ```
3. Run the setup wizard:
   ```bash
   sudo -u openclaw openclaw onboard
   ```
4. Configure channels (Telegram, WhatsApp, Discord) from the dashboard

### Modify API Keys

```bash
sudo nano /home/openclaw/.openclaw/env
sudo systemctl restart openclaw-gateway
```

### Add a Domain Later

1. Set up a DNS A record pointing to the VPS IP
2. Edit the Caddyfile:
   ```bash
   sudo nano /etc/caddy/Caddyfile
   ```
   Replace `:80` with your domain:
   ```
   my-domain.com {
       reverse_proxy localhost:18789
       encode gzip
       header {
           Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
           X-Content-Type-Options "nosniff"
           X-Frame-Options "SAMEORIGIN"
           -Server
       }
   }
   ```
3. Restart Caddy:
   ```bash
   sudo systemctl restart caddy
   ```
   Caddy automatically obtains a Let's Encrypt certificate.

---

## Useful Commands

| Action | Command |
|--------|---------|
| Gateway status | `systemctl status openclaw-gateway` |
| Gateway logs | `journalctl -u openclaw-gateway -f` |
| Restart gateway | `sudo systemctl restart openclaw-gateway` |
| Security report | `sudo /home/openclaw/security-check.sh` |
| CrowdSec alerts | `sudo cscli alerts list` |
| Banned IPs | `sudo cscli decisions list` |
| fail2ban status | `sudo fail2ban-client status sshd` |
| Manual backup | `/home/openclaw/backup.sh` |
| View sandboxes | `docker ps --filter label=openclaw.managed=true` |
| SearXNG status | `docker ps --filter name=searxng` |
| Caddy logs | `sudo journalctl -u caddy -f` |
| AIDE check | `sudo aide --check` |

---

## Git Versioning (Configuration & Memory)

The script installs a Git versioning system for OpenClaw configuration and memory, allowing rollback to a stable version in case of errors.

### Versioned Directories

| Directory | Content | Exclusions |
|-----------|---------|------------|
| `~/.openclaw/` | Configuration (openclaw.json) | credentials/, env, sessions/*.jsonl |
| `~/.openclaw/workspace/` | Memory (MEMORY.md, SOUL.md, memory/) | node_modules/, .cache/ |

### Automatic Commits

- **Hook `git-memory-commit`**: auto-commit on `/new` and `/reset` commands
- **Service `openclaw-git-watcher`**: auto-commit on file changes (30s debounce)

### Git Commands

| Action | Command |
|--------|----------|
| Git status | `~/git-memory-status.sh` |
| Interactive rollback | `~/git-rollback.sh` |
| List config commits | `~/git-rollback.sh --list config` |
| List memory commits | `~/git-rollback.sh --list workspace` |
| Rollback config | `~/git-rollback.sh --rollback <hash> config` |
| Rollback memory | `~/git-rollback.sh --rollback <hash> workspace` |
| View diff | `~/git-rollback.sh --diff <hash> workspace` |
| Watcher logs | `journalctl -u openclaw-git-watcher -f` |

### Multi-Agent Structure

```
~/.openclaw/workspace/
└── memory/
    ├── agents/         # Private memory per agent
    │   └── main/
    ├── shared/         # Shared memory
    │   ├── project/    # Architecture, roadmap
    │   ├── users/      # User profiles
    │   ├── decisions/  # Collective decisions
    │   └── events/     # Inter-agent events
    └── archive/        # Old memories
```

### Complete Guide

See `~/.openclaw/workspace/GIT_MEMORY.md` for the detailed multi-agent management guide.

---

## Security

### 14 Layers of Protection

| Layer | Tool | Function |
|-------|------|----------|
| Cloud perimeter | Hetzner Firewall (manual) | Datacenter-level network filtering |
| Host perimeter | UFW (deny in + deny out) | Strict inbound and outbound filtering |
| Anti brute-force | fail2ban | 24h ban after 3 SSH attempts |
| Collaborative IPS | CrowdSec + iptables bouncer | Behavioral detection + community IPs |
| Kernel network | sysctl hardening | Anti-spoofing, SYN flood, ICMP, martians |
| Authentication | SSH key-only | Password disabled, root disabled |
| File integrity | AIDE | Detects unauthorized modifications (rootkits) |
| System audit | auditd | Critical access logging |
| Application | Caddy headers | HSTS, CSP, X-Frame-Options |
| Process isolation | systemd hardening | NoNewPrivileges, ProtectSystem, PrivateTmp |
| Containers | Docker no-new-privileges | Prevents privilege escalation in sandboxes |
| Secrets | chmod 600 | .env and config files locked |
| Metadata | UFW deny out 169.254.169.254 | Blocks Hetzner metadata access |
| Patches | unattended-upgrades | Automatic security updates |

### Hetzner Recommendation

Also enable the **Hetzner cloud firewall** from the console (console.hetzner.cloud) with the same rules (SSH + 80 + 443) for defense in depth.

---

## Troubleshooting

### Gateway won't start

```bash
# View detailed logs
journalctl -u openclaw-gateway -n 50 --no-pager

# Check configuration
cat /home/openclaw/.openclaw/openclaw.json | jq .

# Check environment variables
cat /home/openclaw/.openclaw/env

# Restart manually
sudo systemctl restart openclaw-gateway
```

### Can't SSH after hardening

The script disables password authentication and root login. Make sure you have:
1. Your SSH key in `/home/openclaw/.ssh/authorized_keys`
2. The correct SSH port (default or the one chosen during installation)

```bash
ssh openclaw@YOUR_IP -p YOUR_PORT -i ~/.ssh/your_key
```

If locked out, use the Hetzner console (VNC access) to fix it.

### SearXNG won't start

```bash
# View container logs
docker logs searxng

# Restart
docker restart searxng

# Recreate if needed
docker rm -f searxng
# Re-run the SearXNG part of the install script
```

### CrowdSec blocking a legitimate IP

```bash
# List active decisions
sudo cscli decisions list

# Unblock an IP
sudo cscli decisions delete --ip X.X.X.X
```

### Re-running after an error

The script is idempotent. Simply re-run it:

```bash
bash /path/to/install.sh
```

Each step checks whether it has already been completed and automatically skips if so.

---

## Important Files

| File | Description |
|------|-------------|
| `/home/openclaw/.openclaw/openclaw.json` | OpenClaw gateway configuration |
| `/home/openclaw/.openclaw/env` | Environment variables (API keys) |
| `/home/openclaw/.openclaw/workspace/` | Agent workspace |
| `/home/openclaw/.openclaw/workspace/GIT_MEMORY.md` | Multi-agent Git guide |
| `/home/openclaw/.openclaw/credentials/` | Channel credentials |
| `/home/openclaw/backup.sh` | Backup script |
| `/home/openclaw/security-check.sh` | Security check script |
| `/home/openclaw/git-rollback.sh` | Git rollback (config/memory) |
| `/home/openclaw/git-memory-status.sh` | Git repos status |
| `/home/openclaw/git-auto-commit.sh` | Git watcher script |
| `/home/openclaw/install-summary.txt` | Installation summary (token) |
| `/etc/caddy/Caddyfile` | Reverse proxy configuration |
| `/etc/systemd/system/openclaw-gateway.service` | Gateway systemd service |
| `/etc/systemd/system/openclaw-git-watcher.service` | Git watcher service |
| `/etc/sysctl.d/99-openclaw-hardening.conf` | Kernel hardening |
| `/etc/ssh/sshd_config.d/99-openclaw-hardening.conf` | SSH hardening |
| `/etc/fail2ban/jail.local` | fail2ban configuration |
| `/var/log/openclaw-install.log` | Installation log |
| `/var/log/openclaw-backup.log` | Backup log |
| `/var/log/aide-check.log` | AIDE integrity report |
