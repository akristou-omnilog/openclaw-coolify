#!/usr/bin/env bash
# =============================================================================
# OpenClaw VPS Installer - Hetzner Optimized (Native Installation)
# =============================================================================
# Installs OpenClaw natively on a VPS with optimal security hardening.
# Docker is used ONLY for sandbox environments and SearXNG.
#
# Features:
#   - Full security hardening (UFW, CrowdSec, fail2ban, kernel sysctl)
#   - Native OpenClaw installation with systemd service
#   - Caddy reverse proxy with automatic HTTPS
#   - Git versioning for config and memory (auto-commit on session events)
#   - File watcher service for real-time commits
#   - Rollback scripts for disaster recovery
#
# Usage:
#   bash install.sh                              # Interactive mode
#   bash install.sh --domain example.com         # With domain
#   bash install.sh --non-interactive --domain example.com --email you@mail.com
#   bash install.sh --dry-run                    # Preview only
#
# Post-install Git commands:
#   ~/git-memory-status.sh                       # View Git status
#   ~/git-rollback.sh                            # Rollback to previous version
#   ~/git-rollback.sh --list workspace           # List memory commits
#
# Tested on: Ubuntu 22.04, Ubuntu 24.04, Debian 12
# =============================================================================
set -euo pipefail

# =============================================================================
# Constants
# =============================================================================
readonly SCRIPT_VERSION="1.0.0"
readonly INSTALL_LOG="/var/log/openclaw-install.log"
readonly DEFAULT_USER="openclaw"
readonly DEFAULT_SSH_PORT=22
readonly DEFAULT_SWAP_SIZE="2G"
readonly DEFAULT_GATEWAY_PORT=18789
readonly SEARXNG_PORT=8888  # Avoid 8080 conflict with CrowdSec LAPI
readonly NODE_MAJOR=22

# =============================================================================
# Color Definitions
# =============================================================================
readonly BOLD='\033[1m'
readonly GREEN='\033[38;2;47;191;113m'
readonly YELLOW='\033[38;2;255;176;32m'
readonly RED='\033[38;2;226;61;45m'
readonly BLUE='\033[38;2;100;149;237m'
readonly CYAN='\033[38;2;0;200;200m'
readonly MUTED='\033[38;2;139;127;119m'
readonly NC='\033[0m'

# =============================================================================
# Script State
# =============================================================================
DOMAIN=""
EMAIL=""
SSH_PORT="${DEFAULT_SSH_PORT}"
OPENCLAW_USER="${DEFAULT_USER}"
SWAP_SIZE="${DEFAULT_SWAP_SIZE}"
NON_INTERACTIVE=false
SKIP_HARDENING=false
DRY_RUN=false
GATEWAY_TOKEN=""

# =============================================================================
# Logging Functions
# =============================================================================
log_info() {
    echo -e "${BLUE}[INFO]${NC} $*" | tee -a "${INSTALL_LOG}" 2>/dev/null || echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $*" | tee -a "${INSTALL_LOG}" 2>/dev/null || echo -e "${GREEN}[OK]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*" | tee -a "${INSTALL_LOG}" 2>/dev/null || echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" | tee -a "${INSTALL_LOG}" 2>/dev/null || echo -e "${RED}[ERROR]${NC} $*"
}

log_step() {
    local step_num="$1"
    shift
    echo ""
    echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${CYAN}  Phase ${step_num}: $*${NC}"
    echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

log_dry() {
    echo -e "${MUTED}[DRY-RUN]${NC} $*"
}

# =============================================================================
# Utility Functions
# =============================================================================
confirm() {
    if $NON_INTERACTIVE; then
        return 0
    fi
    local prompt="${1:-Continue?}"
    echo -en "${YELLOW}${prompt} [y/N]: ${NC}" >&2
    read -r response
    [[ "$response" =~ ^[Yy]$ ]]
}

prompt_value() {
    local prompt="$1"
    local default="${2:-}"
    local result=""

    if $NON_INTERACTIVE; then
        echo "$default"
        return
    fi

    if [[ -n "$default" ]]; then
        echo -en "${BLUE}${prompt}${NC} [${MUTED}${default}${NC}]: " >&2
    else
        echo -en "${BLUE}${prompt}${NC}: " >&2
    fi
    read -r result
    echo "${result:-$default}"
}

prompt_secret() {
    local prompt="$1"
    local result=""

    if $NON_INTERACTIVE; then
        echo ""
        return
    fi

    echo -en "${BLUE}${prompt}${NC} (Enter to skip): " >&2
    read -rs result
    echo "" >&2
    echo "$result"
}

generate_secret() {
    openssl rand -hex 24
}

generate_base64_secret() {
    openssl rand -base64 32
}

is_installed() {
    command -v "$1" &>/dev/null
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use: sudo bash install.sh)"
        exit 1
    fi
}

run_cmd() {
    if $DRY_RUN; then
        log_dry "$*"
        return 0
    fi
    "$@"
}

# =============================================================================
# Error Handler
# =============================================================================
error_handler() {
    local exit_code=$?
    local line_number="${BASH_LINENO[0]}"
    log_error "Installation failed at line ${line_number} (exit code ${exit_code})"
    log_error "Check the log file: ${INSTALL_LOG}"
    log_error "You can safely re-run this script -- it will resume from where it left off."
    exit "$exit_code"
}
trap error_handler ERR

# =============================================================================
# Argument Parsing
# =============================================================================
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --domain)
                DOMAIN="$2"
                shift 2
                ;;
            --email)
                EMAIL="$2"
                shift 2
                ;;
            --ssh-port)
                SSH_PORT="$2"
                shift 2
                ;;
            --user)
                OPENCLAW_USER="$2"
                shift 2
                ;;
            --swap-size)
                SWAP_SIZE="$2"
                shift 2
                ;;
            --non-interactive)
                NON_INTERACTIVE=true
                shift
                ;;
            --skip-hardening)
                SKIP_HARDENING=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

show_help() {
    cat <<'HELP'

  OpenClaw VPS Installer v1.0.0

  Usage: bash install.sh [OPTIONS]

  Options:
    --domain <domain>       Domain name for HTTPS (optional)
    --email <email>         Email for Let's Encrypt (required if domain set)
    --ssh-port <port>       SSH port (default: 22)
    --user <username>       System user (default: openclaw)
    --swap-size <size>      Swap file size (default: 2G)
    --non-interactive       Run without prompts
    --skip-hardening        Skip SSH hardening
    --dry-run               Preview actions without executing
    --help, -h              Show this help

  Examples:
    bash install.sh
    bash install.sh --domain my.example.com --email me@example.com
    bash install.sh --non-interactive --ssh-port 2222
    bash install.sh --dry-run

  Features installed:
    - Security: UFW, CrowdSec, fail2ban, kernel hardening, AIDE, auditd
    - Services: OpenClaw Gateway (systemd), Caddy reverse proxy, SearXNG
    - Docker: Sandbox images for isolated code execution
    - Git versioning: Auto-commit config and memory on session events

  Post-install commands:
    ~/security-check.sh         Show security status
    ~/backup.sh                 Manual backup
    ~/git-memory-status.sh      Git versioning status
    ~/git-rollback.sh           Rollback config/memory to previous commit
    ~/git-rollback.sh --list    List recent commits

  Git versioning:
    Config (~/.openclaw/) and memory (~/.openclaw/workspace/) are versioned.
    Auto-commit triggers: /new, /reset commands + file watcher service.
    Guide: ~/.openclaw/workspace/GIT_MEMORY.md

HELP
}

# =============================================================================
# Preflight Checks
# =============================================================================
detect_os() {
    if [[ ! -f /etc/os-release ]]; then
        log_error "Cannot detect OS. /etc/os-release not found."
        exit 1
    fi

    source /etc/os-release

    case "$ID" in
        ubuntu)
            case "$VERSION_ID" in
                22.04|24.04) ;;
                *)
                    log_error "Ubuntu ${VERSION_ID} is not supported. Use 22.04 or 24.04."
                    exit 1
                    ;;
            esac
            ;;
        debian)
            case "$VERSION_ID" in
                12) ;;
                *)
                    log_error "Debian ${VERSION_ID} is not supported. Use Debian 12."
                    exit 1
                    ;;
            esac
            ;;
        *)
            log_error "OS '${ID}' is not supported. Use Ubuntu 22.04/24.04 or Debian 12."
            exit 1
            ;;
    esac

    log_success "Detected: ${PRETTY_NAME}"
}

preflight_checks() {
    require_root
    detect_os

    # Check disk space (minimum 15GB free)
    local free_gb
    free_gb=$(df -BG / | awk 'NR==2 {print $4}' | tr -d 'G')
    if [[ "$free_gb" -lt 15 ]]; then
        log_error "Insufficient disk space: ${free_gb}GB free. Minimum 15GB required."
        exit 1
    fi
    log_success "Disk space: ${free_gb}GB free"

    # Check RAM (minimum 2GB)
    local total_ram_mb
    total_ram_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
    if [[ "$total_ram_mb" -lt 1800 ]]; then
        log_error "Insufficient RAM: ${total_ram_mb}MB. Minimum 2GB required."
        exit 1
    fi
    if [[ "$total_ram_mb" -lt 3800 ]]; then
        log_warn "RAM: ${total_ram_mb}MB. 4GB+ recommended for optimal performance."
    else
        log_success "RAM: ${total_ram_mb}MB"
    fi

    # Check internet
    if ! curl -s --max-time 5 https://deb.nodesource.com > /dev/null 2>&1; then
        log_error "No internet connectivity. Check your network."
        exit 1
    fi
    log_success "Internet connectivity OK"

    # Create log file
    mkdir -p "$(dirname "${INSTALL_LOG}")"
    touch "${INSTALL_LOG}"
}

# =============================================================================
# Interactive Prompts
# =============================================================================
interactive_prompts() {
    if $NON_INTERACTIVE; then
        return 0
    fi

    echo ""
    echo -e "${BOLD}${CYAN}=====================================================================${NC}"
    echo -e "${BOLD}${CYAN}  OpenClaw VPS Installer v${SCRIPT_VERSION}${NC}"
    echo -e "${BOLD}${CYAN}  Native installation with optimal security${NC}"
    echo -e "${BOLD}${CYAN}=====================================================================${NC}"
    echo ""

    OPENCLAW_USER=$(prompt_value "System username" "$OPENCLAW_USER")
    SSH_PORT=$(prompt_value "SSH port" "$SSH_PORT")
    SWAP_SIZE=$(prompt_value "Swap size" "$SWAP_SIZE")
    DOMAIN=$(prompt_value "Domain name (leave empty for IP-only access)" "$DOMAIN")

    if [[ -n "$DOMAIN" && -z "$EMAIL" ]]; then
        EMAIL=$(prompt_value "Email for Let's Encrypt SSL" "$EMAIL")
        if [[ -z "$EMAIL" ]]; then
            log_warn "No email provided. HTTPS will not be configured even with domain."
        fi
    fi

    echo ""
    echo -e "${BOLD}Configuration summary:${NC}"
    echo -e "  User:       ${CYAN}${OPENCLAW_USER}${NC}"
    echo -e "  SSH port:   ${CYAN}${SSH_PORT}${NC}"
    echo -e "  Swap:       ${CYAN}${SWAP_SIZE}${NC}"
    echo -e "  Domain:     ${CYAN}${DOMAIN:-none}${NC}"
    echo -e "  Email:      ${CYAN}${EMAIL:-none}${NC}"
    echo ""

    if ! confirm "Proceed with installation?"; then
        log_info "Installation cancelled."
        exit 0
    fi
}

# =============================================================================
# Phase 1: System Preparation & Security Hardening
# =============================================================================

update_system() {
    log_info "Updating system packages..."
    run_cmd apt-get update -qq
    run_cmd env DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq
    log_success "System packages updated"
}

install_base_packages() {
    log_info "Installing base packages..."
    run_cmd env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        git curl wget ca-certificates gnupg lsb-release \
        apt-transport-https software-properties-common \
        build-essential python3 python3-pip python3-venv \
        jq lsof openssl sqlite3 unzip \
        ffmpeg imagemagick graphviz \
        ripgrep fd-find fzf bat \
        pandoc poppler-utils \
        ufw fail2ban auditd \
        unattended-upgrades apt-listchanges \
        logrotate
    log_success "Base packages installed"
}

set_timezone() {
    if timedatectl show 2>/dev/null | grep -q "Timezone=UTC"; then
        log_info "Timezone already UTC. Skipping."
        return 0
    fi
    log_info "Setting timezone to UTC..."
    run_cmd timedatectl set-timezone UTC
    log_success "Timezone set to UTC"
}

configure_swap() {
    if swapon --show 2>/dev/null | grep -q "/swapfile"; then
        log_info "Swap already configured. Skipping."
        return 0
    fi
    log_info "Configuring swap (${SWAP_SIZE})..."
    run_cmd fallocate -l "${SWAP_SIZE}" /swapfile
    run_cmd chmod 600 /swapfile
    run_cmd mkswap /swapfile
    run_cmd swapon /swapfile

    if ! grep -q "/swapfile" /etc/fstab; then
        echo "/swapfile none swap sw 0 0" >> /etc/fstab
    fi

    # Optimize swappiness
    if [[ ! -f /etc/sysctl.d/99-swap.conf ]]; then
        cat > /etc/sysctl.d/99-swap.conf <<'EOF'
vm.swappiness=10
vm.vfs_cache_pressure=50
EOF
        sysctl --system > /dev/null 2>&1
    fi
    log_success "Swap configured: ${SWAP_SIZE}"
}

create_user() {
    if id -u "${OPENCLAW_USER}" &>/dev/null; then
        log_info "User '${OPENCLAW_USER}' already exists. Skipping."
    else
        log_info "Creating user '${OPENCLAW_USER}'..."
        run_cmd useradd -m -s /bin/bash -G sudo "${OPENCLAW_USER}"
        # Lock password (SSH key only)
        run_cmd passwd -l "${OPENCLAW_USER}"
        log_success "User '${OPENCLAW_USER}' created"
    fi

    # Copy SSH keys from root
    local user_home
    user_home=$(eval echo ~"${OPENCLAW_USER}")
    local ssh_dir="${user_home}/.ssh"

    if [[ -f /root/.ssh/authorized_keys && ! -f "${ssh_dir}/authorized_keys" ]]; then
        log_info "Copying SSH keys to ${OPENCLAW_USER}..."
        run_cmd mkdir -p "${ssh_dir}"
        run_cmd cp /root/.ssh/authorized_keys "${ssh_dir}/authorized_keys"
        run_cmd chown -R "${OPENCLAW_USER}:${OPENCLAW_USER}" "${ssh_dir}"
        run_cmd chmod 700 "${ssh_dir}"
        run_cmd chmod 600 "${ssh_dir}/authorized_keys"
        log_success "SSH keys copied"
    elif [[ ! -f /root/.ssh/authorized_keys ]]; then
        log_warn "No SSH keys found in /root/.ssh/authorized_keys"
        log_warn "Make sure to add SSH keys for '${OPENCLAW_USER}' before SSH hardening!"
    fi
}

harden_ssh() {
    if $SKIP_HARDENING; then
        log_warn "SSH hardening skipped (--skip-hardening)"
        return 0
    fi

    local config="/etc/ssh/sshd_config.d/99-openclaw-hardening.conf"
    if [[ -f "$config" ]]; then
        log_info "SSH hardening already configured. Skipping."
        return 0
    fi

    # Verify SSH keys exist for the new user before locking root out
    local user_home
    user_home=$(eval echo ~"${OPENCLAW_USER}")
    if [[ ! -f "${user_home}/.ssh/authorized_keys" ]]; then
        log_warn "================================================================"
        log_warn "  WARNING: No SSH keys found for '${OPENCLAW_USER}'"
        log_warn "  SSH hardening will disable root login and password auth."
        log_warn "  You may be LOCKED OUT if you proceed without SSH keys!"
        log_warn "================================================================"
        if ! confirm "Proceed with SSH hardening anyway?"; then
            log_warn "SSH hardening skipped. Run script again after adding SSH keys."
            return 0
        fi
    fi

    log_info "Hardening SSH configuration..."

    # Backup original config
    if [[ -f /etc/ssh/sshd_config && ! -f /etc/ssh/sshd_config.backup ]]; then
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    fi

    run_cmd tee "$config" > /dev/null <<EOF
# OpenClaw SSH Hardening - generated by install.sh
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
LoginGraceTime 20
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
PermitEmptyPasswords no
Port ${SSH_PORT}
EOF

    # Ubuntu 24.04 uses 'ssh', older Ubuntu/Debian use 'sshd'
    if systemctl list-units --type=service --all | grep -q 'ssh\.service'; then
        run_cmd systemctl restart ssh
    else
        run_cmd systemctl restart sshd
    fi
    log_success "SSH hardened (port ${SSH_PORT}, key-only, root disabled)"
}

setup_firewall() {
    if ufw status 2>/dev/null | grep -q "Status: active"; then
        log_info "UFW firewall already active. Verifying rules..."
    else
        log_info "Configuring UFW firewall..."
    fi

    run_cmd ufw default deny incoming
    run_cmd ufw default deny outgoing

    # Incoming
    run_cmd ufw allow "${SSH_PORT}/tcp" comment "SSH"
    run_cmd ufw allow 80/tcp comment "HTTP"
    run_cmd ufw allow 443/tcp comment "HTTPS"

    # Outgoing (restrictive)
    run_cmd ufw allow out 53 comment "DNS"
    run_cmd ufw allow out 80/tcp comment "HTTP out"
    run_cmd ufw allow out 443/tcp comment "HTTPS out"
    run_cmd ufw allow out 123/udp comment "NTP"

    # Block Hetzner metadata service
    run_cmd ufw deny out to 169.254.169.254 comment "Block metadata service"

    run_cmd ufw --force enable
    log_success "UFW firewall active (deny in + deny out, SSH/${SSH_PORT} + 80 + 443 allowed)"
}

setup_crowdsec() {
    if is_installed cscli; then
        log_info "CrowdSec already installed. Skipping."
        return 0
    fi

    log_info "Installing CrowdSec (collaborative IPS)..."
    # Add CrowdSec APT repository
    run_cmd bash -c 'curl -s https://install.crowdsec.net | bash'
    # Install CrowdSec engine + firewall bouncer
    run_cmd apt-get install -y -qq crowdsec crowdsec-firewall-bouncer-iptables
    # Refresh command hash after install
    hash -r

    # Install security collections
    log_info "Installing CrowdSec security collections..."
    run_cmd /usr/bin/cscli collections install crowdsecurity/linux
    run_cmd /usr/bin/cscli collections install crowdsecurity/sshd
    run_cmd /usr/bin/cscli collections install crowdsecurity/http-cve

    run_cmd systemctl enable crowdsec
    run_cmd systemctl restart crowdsec
    log_success "CrowdSec installed with linux/sshd/http-cve collections"
}

setup_fail2ban() {
    if systemctl is-active fail2ban &>/dev/null; then
        log_info "fail2ban already active. Skipping."
        return 0
    fi

    log_info "Configuring fail2ban..."
    run_cmd tee /etc/fail2ban/jail.local > /dev/null <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
backend = systemd
banaction = ufw

[sshd]
enabled = true
port = ${SSH_PORT}
mode = aggressive
maxretry = 3
bantime = 86400
EOF

    run_cmd systemctl enable fail2ban
    run_cmd systemctl restart fail2ban
    log_success "fail2ban configured (SSH: ban 24h after 3 attempts)"
}

harden_kernel() {
    local config="/etc/sysctl.d/99-openclaw-hardening.conf"
    if [[ -f "$config" ]]; then
        log_info "Kernel hardening already configured. Skipping."
        return 0
    fi

    log_info "Applying kernel hardening (sysctl)..."
    run_cmd tee "$config" > /dev/null <<'EOF'
# OpenClaw Kernel Hardening

# === Network Protection ===
# Anti-spoofing: verify packet source
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP redirects (prevent MitM)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0

# Block source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Log martian packets
net.ipv4.conf.all.log_martians = 1

# Anti-Smurf
net.ipv4.icmp_echo_ignore_broadcasts = 1

# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2

# Ignore bogus ICMP responses
net.ipv4.icmp_ignore_bogus_error_responses = 1

# === Kernel Protection ===
# Restrict kernel pointer access
kernel.kptr_restrict = 2

# Restrict kernel log access
kernel.dmesg_restrict = 1

# Disable unprivileged eBPF
kernel.unprivileged_bpf_disabled = 1

# BPF JIT hardening
net.core.bpf_jit_harden = 2

# Restrict ptrace (anti-injection)
kernel.yama.ptrace_scope = 1

# Disable core dumps for setuid
fs.suid_dumpable = 0

# === Docker Compatible ===
# IP forwarding required by Docker
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# File limits for Docker
fs.file-max = 2097152
fs.inotify.max_user_watches = 524288
fs.inotify.max_user_instances = 512
EOF

    run_cmd sysctl --system > /dev/null 2>&1
    log_success "Kernel hardened (anti-spoofing, SYN flood, ICMP, ptrace, eBPF)"
}

setup_aide() {
    if is_installed aide; then
        log_info "AIDE already installed. Skipping."
        return 0
    fi

    log_info "Installing AIDE (file integrity monitoring)..."
    run_cmd env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq aide

    log_info "Initializing AIDE database (this may take a few minutes)..."
    run_cmd aideinit
    if [[ -f /var/lib/aide/aide.db.new ]]; then
        run_cmd cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    fi

    # Daily cron at 5 AM
    run_cmd tee /etc/cron.d/aide-check > /dev/null <<'EOF'
0 5 * * * root /usr/bin/aide.wrapper --check --config /etc/aide/aide.conf > /var/log/aide-check.log 2>&1
EOF

    log_success "AIDE installed (daily integrity check at 5 AM)"
}

setup_auditd() {
    if systemctl is-active auditd &>/dev/null; then
        log_info "auditd already active. Checking rules..."
    else
        log_info "Configuring auditd..."
        run_cmd systemctl enable auditd
    fi

    local rules_file="/etc/audit/rules.d/openclaw.rules"
    if [[ -f "$rules_file" ]]; then
        log_info "Audit rules already configured. Skipping."
        return 0
    fi

    local user_home
    user_home=$(eval echo ~"${OPENCLAW_USER}")

    run_cmd tee "$rules_file" > /dev/null <<EOF
# OpenClaw Audit Rules
# Monitor critical file modifications
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k sudo_changes
-w /etc/ssh/sshd_config -p wa -k ssh_config
-w ${user_home}/.openclaw/openclaw.json -p wa -k openclaw_config
# Monitor Docker socket
-w /var/run/docker.sock -p wa -k docker_socket
# Monitor root command execution
-a always,exit -F arch=b64 -S execve -F euid=0 -k root_commands
EOF

    run_cmd systemctl restart auditd
    log_success "Audit rules configured (identity, sudo, SSH, Docker, root commands)"
}

setup_unattended_upgrades() {
    if dpkg -l unattended-upgrades 2>/dev/null | grep -q "^ii"; then
        log_info "Unattended-upgrades already configured. Skipping."
        return 0
    fi

    log_info "Configuring automatic security updates..."
    run_cmd env DEBIAN_FRONTEND=noninteractive dpkg-reconfigure -plow unattended-upgrades

    run_cmd tee /etc/apt/apt.conf.d/52openclaw-upgrades > /dev/null <<'EOF'
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
EOF

    log_success "Automatic security updates enabled (no auto-reboot)"
}

# =============================================================================
# Phase 2: Docker Installation (Sandboxes Only)
# =============================================================================

install_docker() {
    if is_installed docker; then
        log_info "Docker already installed ($(docker --version 2>/dev/null | head -1)). Skipping."
    else
        log_info "Installing Docker Engine..."
        run_cmd bash -c 'curl -fsSL https://get.docker.com | sh'
        log_success "Docker Engine installed"
    fi

    # Add user to docker group
    if ! groups "${OPENCLAW_USER}" 2>/dev/null | grep -q docker; then
        run_cmd usermod -aG docker "${OPENCLAW_USER}"
        log_success "User '${OPENCLAW_USER}' added to docker group"
    fi
}

configure_docker_daemon() {
    local config="/etc/docker/daemon.json"
    if [[ -f "$config" ]]; then
        log_info "Docker daemon already configured. Skipping."
        return 0
    fi

    log_info "Configuring Docker daemon (security + log rotation)..."
    run_cmd mkdir -p /etc/docker
    run_cmd tee "$config" > /dev/null <<'EOF'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "live-restore": true,
  "no-new-privileges": true,
  "default-ulimits": {
    "nofile": { "Name": "nofile", "Hard": 65535, "Soft": 65535 }
  }
}
EOF

    run_cmd systemctl restart docker
    run_cmd systemctl enable docker
    log_success "Docker daemon configured (no-new-privileges, log rotation)"
}

setup_searxng() {
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^searxng$"; then
        log_info "SearXNG container already running. Skipping."
        return 0
    fi

    # Remove stopped/failed container if exists
    if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^searxng$"; then
        log_info "Removing stopped SearXNG container..."
        run_cmd docker rm -f searxng
    fi

    # Check if the port is already in use by something else
    if ss -tlnp 2>/dev/null | grep -q ":${SEARXNG_PORT} "; then
        log_warn "Port ${SEARXNG_PORT} is already in use. Checking what is using it..."
        local pid
        pid=$(ss -tlnp 2>/dev/null | grep ":${SEARXNG_PORT} " | grep -oP 'pid=\K[0-9]+' | head -1)
        if [[ -n "$pid" ]]; then
            local pname
            pname=$(ps -p "$pid" -o comm= 2>/dev/null || echo "unknown")
            log_warn "Port ${SEARXNG_PORT} is used by PID ${pid} (${pname})"
        fi
        log_warn "SearXNG cannot start. Free port ${SEARXNG_PORT} or change SEARXNG_PORT and re-run."
        return 1
    fi

    log_info "Starting SearXNG (private search engine)..."
    local searxng_secret
    searxng_secret=$(generate_base64_secret)

    run_cmd docker run -d \
        --name searxng \
        --restart unless-stopped \
        -p "127.0.0.1:${SEARXNG_PORT}:8080" \
        -v searxng-data:/var/lib/searxng \
        -e "SEARXNG_BASE_URL=http://localhost:${SEARXNG_PORT}" \
        -e "SEARXNG_SERVER_SECRET_KEY=${searxng_secret}" \
        --cap-drop ALL \
        --cap-add CHOWN \
        --cap-add SETGID \
        --cap-add SETUID \
        --security-opt no-new-privileges:true \
        searxng/searxng:latest

    # Wait briefly and verify container is actually running
    sleep 2
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^searxng$"; then
        log_success "SearXNG running on localhost:${SEARXNG_PORT}"
    else
        log_error "SearXNG container failed to start. Check: docker logs searxng"
        return 1
    fi
}

setup_sandbox_images() {
    log_info "Pulling sandbox images..."

    # Base sandbox image
    if docker image inspect openclaw-sandbox:bookworm-slim &>/dev/null; then
        log_info "Sandbox base image already exists. Skipping."
    else
        run_cmd docker pull python:3.11-slim-bookworm
        run_cmd docker tag python:3.11-slim-bookworm openclaw-sandbox:bookworm-slim
        log_success "Sandbox base image ready (openclaw-sandbox:bookworm-slim)"
    fi

    # Browser sandbox image
    if docker image inspect openclaw-sandbox-browser:bookworm-slim &>/dev/null; then
        log_info "Sandbox browser image already exists. Skipping."
    else
        run_cmd docker pull mcr.microsoft.com/playwright:v1.41.0-jammy
        run_cmd docker tag mcr.microsoft.com/playwright:v1.41.0-jammy openclaw-sandbox-browser:bookworm-slim
        log_success "Sandbox browser image ready (openclaw-sandbox-browser:bookworm-slim)"
    fi
}

# =============================================================================
# Phase 3: OpenClaw Native Installation
# =============================================================================

install_nodejs() {
    if is_installed node; then
        local node_version
        node_version=$(node --version 2>/dev/null)
        local node_major
        node_major=$(echo "$node_version" | cut -d'.' -f1 | tr -d 'v')
        if [[ "$node_major" -ge "$NODE_MAJOR" ]]; then
            log_info "Node.js ${node_version} already installed. Skipping."
            return 0
        fi
        log_warn "Node.js ${node_version} is too old. Upgrading to v${NODE_MAJOR}..."
    fi

    log_info "Installing Node.js ${NODE_MAJOR}..."
    run_cmd bash -c "curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash -"
    run_cmd apt-get install -y -qq nodejs
    log_success "Node.js $(node --version) installed"
}

install_extra_tools() {
    local user_home
    user_home=$(eval echo ~"${OPENCLAW_USER}")

    # Bun
    if is_installed bun; then
        log_info "Bun already installed. Skipping."
    else
        log_info "Installing Bun..."
        run_cmd sudo -u "${OPENCLAW_USER}" bash -c 'curl -fsSL https://bun.sh/install | bash'
        log_success "Bun installed"
    fi

    # Go
    if [[ -d /usr/local/go ]]; then
        log_info "Go already installed. Skipping."
    else
        log_info "Installing Go 1.23.4..."
        local arch
        arch=$(dpkg --print-architecture)
        if [[ "$arch" == "amd64" ]]; then
            arch="amd64"
        elif [[ "$arch" == "arm64" ]]; then
            arch="arm64"
        fi
        run_cmd wget -q "https://go.dev/dl/go1.23.4.linux-${arch}.tar.gz" -O /tmp/go.tar.gz
        run_cmd tar -C /usr/local -xzf /tmp/go.tar.gz
        rm -f /tmp/go.tar.gz

        # Add to system profile
        if [[ ! -f /etc/profile.d/go.sh ]]; then
            echo 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile.d/go.sh
        fi
        log_success "Go installed"
    fi

    # Cloudflared
    if is_installed cloudflared; then
        log_info "Cloudflared already installed. Skipping."
    else
        log_info "Installing Cloudflared..."
        local arch
        arch=$(dpkg --print-architecture)
        run_cmd curl -L "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${arch}.deb" -o /tmp/cloudflared.deb
        run_cmd dpkg -i /tmp/cloudflared.deb
        rm -f /tmp/cloudflared.deb
        log_success "Cloudflared installed"
    fi

    # GitHub CLI
    if is_installed gh; then
        log_info "GitHub CLI already installed. Skipping."
    else
        log_info "Installing GitHub CLI..."
        run_cmd bash -c 'curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg 2>/dev/null'
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | tee /etc/apt/sources.list.d/github-cli.list > /dev/null
        run_cmd apt-get update -qq
        run_cmd apt-get install -y -qq gh
        log_success "GitHub CLI installed"
    fi
}

install_openclaw() {
    local user_home
    user_home=$(eval echo ~"${OPENCLAW_USER}")

    if sudo -u "${OPENCLAW_USER}" bash -c "export PATH=\"${user_home}/.npm-global/bin:\$PATH\" && command -v openclaw" &>/dev/null; then
        log_info "OpenClaw already installed. Skipping."
        return 0
    fi

    log_info "Installing OpenClaw..."

    # Configure npm global prefix in user's home to avoid /usr/lib permission issues
    run_cmd sudo -u "${OPENCLAW_USER}" mkdir -p "${user_home}/.npm-global"
    run_cmd sudo -u "${OPENCLAW_USER}" bash -c "npm config set prefix '${user_home}/.npm-global'"
    run_cmd sudo -u "${OPENCLAW_USER}" bash -c "export PATH=\"${user_home}/.npm-global/bin:\$PATH\" && npm install -g openclaw@latest"

    # Add npm-global/bin to user's PATH permanently
    if ! grep -q '.npm-global/bin' "${user_home}/.profile" 2>/dev/null; then
        echo 'export PATH="$HOME/.npm-global/bin:$PATH"' | sudo -u "${OPENCLAW_USER}" tee -a "${user_home}/.profile" > /dev/null
    fi

    # Create symlink in /usr/local/bin so systemd and other users can find it
    if [[ -f "${user_home}/.npm-global/bin/openclaw" ]]; then
        ln -sf "${user_home}/.npm-global/bin/openclaw" /usr/local/bin/openclaw
    fi

    log_success "OpenClaw installed ($(sudo -u "${OPENCLAW_USER}" bash -c "export PATH=\"${user_home}/.npm-global/bin:\$PATH\" && openclaw --version 2>/dev/null || echo 'latest'"))"
}

configure_openclaw() {
    local user_home
    user_home=$(eval echo ~"${OPENCLAW_USER}")
    local openclaw_dir="${user_home}/.openclaw"
    local config_file="${openclaw_dir}/openclaw.json"
    local env_file="${openclaw_dir}/env"
    local workspace_dir="${openclaw_dir}/workspace"

    # Create directories
    run_cmd sudo -u "${OPENCLAW_USER}" mkdir -p "${openclaw_dir}/credentials"
    run_cmd sudo -u "${OPENCLAW_USER}" mkdir -p "${workspace_dir}"
    run_cmd chmod 700 "${openclaw_dir}"
    run_cmd chmod 700 "${openclaw_dir}/credentials"

    # Generate gateway token
    GATEWAY_TOKEN=$(generate_secret)

    # Create config file
    if [[ -f "$config_file" ]]; then
        log_info "OpenClaw config already exists. Preserving."
        # Extract existing token
        GATEWAY_TOKEN=$(jq -r '.gateway.auth.token // empty' "$config_file" 2>/dev/null || echo "$GATEWAY_TOKEN")
    else
        log_info "Creating OpenClaw configuration..."

        local public_url="http://localhost:${DEFAULT_GATEWAY_PORT}"
        if [[ -n "$DOMAIN" ]]; then
            if [[ -n "$EMAIL" ]]; then
                public_url="https://${DOMAIN}"
            else
                public_url="http://${DOMAIN}"
            fi
        fi

        run_cmd tee "$config_file" > /dev/null <<EOF
{
  "gateway": {
    "port": ${DEFAULT_GATEWAY_PORT},
    "bind": "lan",
    "auth": {
      "mode": "token",
      "token": "${GATEWAY_TOKEN}"
    },
    "trustedProxies": ["127.0.0.1"],
    "controlUi": {
      "enabled": true
    }
  },
  "agents": {
    "defaults": {
      "workspace": "${workspace_dir}",
      "sandbox": {
        "mode": "non-main",
        "scope": "session",
        "browser": {
          "enabled": true
        }
      }
    },
    "list": [
      {
        "id": "main",
        "default": true,
        "name": "default",
        "workspace": "${workspace_dir}"
      }
    ]
  }
}
EOF
        log_success "OpenClaw configuration created"
    fi

    # Create env file
    if [[ -f "$env_file" ]]; then
        log_info "Environment file already exists. Preserving."
    else
        log_info "Creating environment file..."

        # Collect API keys interactively
        local openai_key="" anthropic_key="" gemini_key="" minimax_key=""
        local groq_key="" mistral_key="" nvidia_key="" kimi_key=""
        local opencode_key="" telegram_token="" github_token=""

        if ! $NON_INTERACTIVE; then
            echo ""
            echo -e "${BOLD}API Keys Configuration${NC} (press Enter to skip any)"
            echo -e "${MUTED}You can add these later by editing ${env_file}${NC}"
            echo ""
            openai_key=$(prompt_secret "  OpenAI API key")
            anthropic_key=$(prompt_secret "  Anthropic API key")
            gemini_key=$(prompt_secret "  Gemini API key")
            minimax_key=$(prompt_secret "  MiniMax API key")
            groq_key=$(prompt_secret "  Groq API key")
            mistral_key=$(prompt_secret "  Mistral API key")
            nvidia_key=$(prompt_secret "  NVIDIA API key")
            kimi_key=$(prompt_secret "  Kimi API key")
            opencode_key=$(prompt_secret "  OpenCode API key")
            telegram_token=$(prompt_secret "  Telegram Bot token")
            github_token=$(prompt_secret "  GitHub token")
        fi

        run_cmd tee "$env_file" > /dev/null <<EOF
# OpenClaw Environment - Generated by install.sh
# Modify API keys here and restart: systemctl restart openclaw-gateway

OPENCLAW_STATE_DIR=${openclaw_dir}
OPENCLAW_WORKSPACE=${workspace_dir}
DOCKER_HOST=unix:///var/run/docker.sock
SEARXNG_URL=http://localhost:${SEARXNG_PORT}
NODE_ENV=production
NODE_OPTIONS=--max-old-space-size=4096

# AI Provider API Keys
OPENAI_API_KEY=${openai_key}
ANTHROPIC_API_KEY=${anthropic_key}
GEMINI_API_KEY=${gemini_key}
MINIMAX_API_KEY=${minimax_key}
GROQ_API_KEY=${groq_key}
MISTRAL_API_KEY=${mistral_key}
NVIDIA_API_KEY=${nvidia_key}
KIMI_API_KEY=${kimi_key}
OPENCODE_API_KEY=${opencode_key}
MOONSHOT_API_KEY=${kimi_key}

# Integrations
TELEGRAM_BOT_TOKEN=${telegram_token}
ELEVENLABS_API_KEY=
GOOGLE_MAPS_API_KEY=
NANOBANANA_API_KEY=

# GitHub
GITHUB_TOKEN=${github_token}
GITHUB_USERNAME=
GITHUB_EMAIL=

# Cloudflare Tunnel (optional, for public sandbox URLs)
CF_TUNNEL_TOKEN=

# Vercel (optional)
VERCEL_TOKEN=
VERCEL_ORG_ID=
VERCEL_PROJECT_ID=
EOF

        log_success "Environment file created"
    fi

    # Set permissions
    run_cmd chown -R "${OPENCLAW_USER}:${OPENCLAW_USER}" "${openclaw_dir}"
    run_cmd chmod 600 "$config_file"
    run_cmd chmod 600 "$env_file"
}

setup_systemd_service() {
    local service_file="/etc/systemd/system/openclaw-gateway.service"
    if [[ -f "$service_file" ]]; then
        log_info "Systemd service already exists. Skipping."
        return 0
    fi

    local user_home
    user_home=$(eval echo ~"${OPENCLAW_USER}")

    # Find openclaw binary path (check symlink in /usr/local/bin first, then npm-global)
    local openclaw_bin="/usr/local/bin/openclaw"
    if [[ ! -f "$openclaw_bin" ]]; then
        openclaw_bin="${user_home}/.npm-global/bin/openclaw"
    fi

    log_info "Creating systemd service..."
    run_cmd tee "$service_file" > /dev/null <<EOF
[Unit]
Description=OpenClaw Gateway
After=network-online.target docker.service
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
User=${OPENCLAW_USER}
Group=${OPENCLAW_USER}
EnvironmentFile=${user_home}/.openclaw/env
ExecStart=${openclaw_bin} gateway --port ${DEFAULT_GATEWAY_PORT}
Restart=always
RestartSec=5
WorkingDirectory=${user_home}
LimitNOFILE=65535

# Security Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=${user_home}/.openclaw
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

[Install]
WantedBy=multi-user.target
EOF

    run_cmd systemctl daemon-reload
    run_cmd systemctl enable openclaw-gateway
    run_cmd systemctl start openclaw-gateway
    log_success "OpenClaw gateway service started (systemd)"
}

# =============================================================================
# Phase 4: Caddy Reverse Proxy
# =============================================================================

install_caddy() {
    if is_installed caddy; then
        log_info "Caddy already installed. Skipping."
        return 0
    fi

    log_info "Installing Caddy..."
    run_cmd bash -c 'curl -1sLf "https://dl.cloudsmith.io/public/caddy/stable/gpg.key" | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg 2>/dev/null'
    run_cmd bash -c 'curl -1sLf "https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt" | tee /etc/apt/sources.list.d/caddy-stable.list > /dev/null'
    run_cmd apt-get update -qq
    run_cmd apt-get install -y -qq caddy
    log_success "Caddy installed"
}

configure_caddy() {
    local caddyfile="/etc/caddy/Caddyfile"

    log_info "Configuring Caddy reverse proxy..."

    # Create log directory
    run_cmd mkdir -p /var/log/caddy
    run_cmd chown caddy:caddy /var/log/caddy

    if [[ -n "$DOMAIN" && -n "$EMAIL" ]]; then
        # With domain: automatic HTTPS
        run_cmd tee "$caddyfile" > /dev/null <<EOF
# OpenClaw Reverse Proxy - HTTPS
# Generated by install.sh

${DOMAIN} {
    reverse_proxy localhost:${DEFAULT_GATEWAY_PORT}

    encode gzip

    # Security headers
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "SAMEORIGIN"
        X-XSS-Protection "1; mode=block"
        Referrer-Policy "strict-origin-when-cross-origin"
        Permissions-Policy "camera=(), microphone=(), geolocation=()"
        -Server
    }

    # Access logs
    log {
        output file /var/log/caddy/access.log {
            roll_size 10mb
            roll_keep 5
        }
    }
}
EOF
        log_success "Caddy configured with HTTPS for ${DOMAIN}"
    else
        # Without domain: HTTP only
        run_cmd tee "$caddyfile" > /dev/null <<EOF
# OpenClaw Reverse Proxy - HTTP (no domain)
# Generated by install.sh
# To enable HTTPS, replace :80 with your domain and restart Caddy:
#   sudo systemctl restart caddy

:80 {
    reverse_proxy localhost:${DEFAULT_GATEWAY_PORT}

    header -Server

    log {
        output file /var/log/caddy/access.log {
            roll_size 10mb
            roll_keep 5
        }
    }
}
EOF
        log_success "Caddy configured (HTTP mode, no domain)"
    fi

    run_cmd systemctl enable caddy
    run_cmd systemctl restart caddy

    # Add rate limiting via UFW
    run_cmd ufw limit proto tcp from any to any port 80 comment "Rate limit HTTP" 2>/dev/null || true
    run_cmd ufw limit proto tcp from any to any port 443 comment "Rate limit HTTPS" 2>/dev/null || true
}

# =============================================================================
# Phase 5: Post-Installation
# =============================================================================

setup_backup() {
    local user_home
    user_home=$(eval echo ~"${OPENCLAW_USER}")
    local backup_script="${user_home}/backup.sh"
    local backup_dir="${user_home}/backups"

    if [[ -f "$backup_script" ]]; then
        log_info "Backup script already exists. Skipping."
        return 0
    fi

    log_info "Creating backup script..."
    run_cmd mkdir -p "$backup_dir"
    run_cmd chown "${OPENCLAW_USER}:${OPENCLAW_USER}" "$backup_dir"
    run_cmd chmod 700 "$backup_dir"

    run_cmd tee "$backup_script" > /dev/null <<BACKUP
#!/bin/bash
# OpenClaw Backup Script - Generated by install.sh
set -euo pipefail

BACKUP_DIR="${backup_dir}"
DATE=\$(date +%Y%m%d_%H%M%S)
OPENCLAW_DIR="${user_home}/.openclaw"

echo "[\$(date)] Starting backup..."

# Backup OpenClaw config and workspace
tar czf "\${BACKUP_DIR}/openclaw_\${DATE}.tar.gz" \\
    -C "\${OPENCLAW_DIR}" \\
    --exclude="*/node_modules" \\
    --exclude="*/.cache" \\
    . 2>/dev/null || true

# Backup SearXNG volume
docker run --rm \\
    -v searxng-data:/source:ro \\
    -v "\${BACKUP_DIR}":/backup \\
    alpine tar czf "/backup/searxng_\${DATE}.tar.gz" -C /source . 2>/dev/null || true

# Retention: keep last 7 days
find "\${BACKUP_DIR}" -name "*.tar.gz" -mtime +7 -delete 2>/dev/null || true

echo "[\$(date)] Backup complete: \${BACKUP_DIR}"
ls -lh "\${BACKUP_DIR}"/openclaw_\${DATE}.tar.gz 2>/dev/null || true
BACKUP

    run_cmd chown "${OPENCLAW_USER}:${OPENCLAW_USER}" "$backup_script"
    run_cmd chmod 700 "$backup_script"

    # Add cron job (2 AM daily)
    local cron_entry="0 2 * * * ${OPENCLAW_USER} ${backup_script} >> /var/log/openclaw-backup.log 2>&1"
    if ! grep -qF "$backup_script" /etc/cron.d/openclaw-backup 2>/dev/null; then
        echo "$cron_entry" > /etc/cron.d/openclaw-backup
    fi

    log_success "Daily backup configured (2 AM, 7-day retention)"
}

setup_git_versioning() {
    local user_home
    user_home=$(eval echo ~"${OPENCLAW_USER}")
    local openclaw_dir="${user_home}/.openclaw"
    local workspace_dir="${openclaw_dir}/workspace"
    local hooks_dir="${openclaw_dir}/hooks"

    # Check if already configured
    if [[ -d "${openclaw_dir}/.git" && -d "${workspace_dir}/.git" ]]; then
        log_info "Git versioning already configured. Skipping."
        return 0
    fi

    # Install inotify-tools for file watching
    if ! is_installed inotifywait; then
        log_info "Installing inotify-tools..."
        run_cmd apt-get install -y -qq inotify-tools
    fi

    log_info "Configuring Git versioning for config and memory..."

    # === 1. Initialize Git for Config Directory ===
    if [[ ! -d "${openclaw_dir}/.git" ]]; then
        log_info "Initializing Git repository for config..."
        run_cmd sudo -u "${OPENCLAW_USER}" bash -c "cd '${openclaw_dir}' && git init"
        run_cmd sudo -u "${OPENCLAW_USER}" bash -c "cd '${openclaw_dir}' && git config user.email 'agent@openclaw.local'"
        run_cmd sudo -u "${OPENCLAW_USER}" bash -c "cd '${openclaw_dir}' && git config user.name 'OpenClaw-Agent'"

        # Create .gitignore for config (exclude sensitive files)
        run_cmd tee "${openclaw_dir}/.gitignore" > /dev/null <<'GITIGNORE'
# OpenClaw Config Git Ignore
# Security: Never version credentials or tokens

# Sensitive directories
credentials/
.credentials/

# Environment files with secrets
env
.env
*.env

# Session transcripts (may contain sensitive data)
agents/*/sessions/*.jsonl

# Temporary files
*.tmp
*.temp
*.swp
*~

# Logs
*.log
logs/

# Cache
.cache/
node_modules/

# OS files
.DS_Store
Thumbs.db
GITIGNORE

        run_cmd chown "${OPENCLAW_USER}:${OPENCLAW_USER}" "${openclaw_dir}/.gitignore"

        # Initial commit for config
        run_cmd sudo -u "${OPENCLAW_USER}" bash -c "cd '${openclaw_dir}' && git add -A && git commit -m 'Initial commit: OpenClaw configuration' --allow-empty"
        log_success "Git repository initialized for config"
    fi

    # === 2. Initialize Git for Workspace (Memory) ===
    if [[ ! -d "${workspace_dir}/.git" ]]; then
        log_info "Initializing Git repository for workspace/memory..."
        run_cmd sudo -u "${OPENCLAW_USER}" mkdir -p "${workspace_dir}"
        run_cmd sudo -u "${OPENCLAW_USER}" bash -c "cd '${workspace_dir}' && git init"
        run_cmd sudo -u "${OPENCLAW_USER}" bash -c "cd '${workspace_dir}' && git config user.email 'agent@openclaw.local'"
        run_cmd sudo -u "${OPENCLAW_USER}" bash -c "cd '${workspace_dir}' && git config user.name 'OpenClaw-Agent'"

        # Create multi-agent directory structure
        run_cmd sudo -u "${OPENCLAW_USER}" mkdir -p "${workspace_dir}/memory/agents/main"
        run_cmd sudo -u "${OPENCLAW_USER}" mkdir -p "${workspace_dir}/memory/shared/project"
        run_cmd sudo -u "${OPENCLAW_USER}" mkdir -p "${workspace_dir}/memory/shared/users"
        run_cmd sudo -u "${OPENCLAW_USER}" mkdir -p "${workspace_dir}/memory/shared/decisions"
        run_cmd sudo -u "${OPENCLAW_USER}" mkdir -p "${workspace_dir}/memory/shared/events"
        run_cmd sudo -u "${OPENCLAW_USER}" mkdir -p "${workspace_dir}/memory/archive"

        # Create .gitignore for workspace
        run_cmd tee "${workspace_dir}/.gitignore" > /dev/null <<'GITIGNORE'
# OpenClaw Workspace Git Ignore

# Dependencies
node_modules/
.npm/
.bun/

# Cache and temp
.cache/
*.tmp
*.temp
*.swp
*~

# Build outputs
dist/
build/
out/

# OS files
.DS_Store
Thumbs.db

# Large binary files
*.zip
*.tar.gz
*.7z
*.rar

# Sandbox artifacts
.sandbox/
GITIGNORE

        run_cmd chown "${OPENCLAW_USER}:${OPENCLAW_USER}" "${workspace_dir}/.gitignore"

        # Initial commit for workspace
        run_cmd sudo -u "${OPENCLAW_USER}" bash -c "cd '${workspace_dir}' && git add -A && git commit -m 'Initial commit: OpenClaw workspace with multi-agent structure' --allow-empty"
        log_success "Git repository initialized for workspace"
    fi

    # === 3. Create GIT_MEMORY.md Guide ===
    setup_git_memory_guide

    # === 4. Create git-memory-commit Hook ===
    setup_git_memory_hook

    # === 5. Create Utility Scripts ===
    setup_git_rollback_script
    setup_git_status_script

    # === 6. Setup File Watcher Service ===
    setup_git_watcher_service

    log_success "Git versioning configured (config + workspace)"
}

setup_git_memory_guide() {
    local user_home
    user_home=$(eval echo ~"${OPENCLAW_USER}")
    local workspace_dir="${user_home}/.openclaw/workspace"
    local guide_file="${workspace_dir}/GIT_MEMORY.md"

    if [[ -f "$guide_file" ]]; then
        log_info "GIT_MEMORY.md already exists. Skipping."
        return 0
    fi

    log_info "Creating GIT_MEMORY.md guide..."
    run_cmd tee "$guide_file" > /dev/null <<'GITMEMORY'
# Configuration Git Memory - Eviter la Derive & Gestion Multi-Agent

Tu es un assistant IA dans un ecosysteme multi-agents. Chaque agent a une memoire versionnee via Git, avec possibilite de partage, isolation, et synchronisation entre agents.

---

## Architecture de la Memoire

### Structure des dossiers

```
~/.openclaw/
├── .git/                    # Repo Git pour config
├── openclaw.json            # Configuration (versionnee)
└── workspace/
    ├── .git/                # Repo Git pour memoire
    ├── MEMORY.md            # Memoire long terme
    ├── SOUL.md              # Persona agent
    └── memory/
        ├── agents/          # Memoire privee par agent
        │   └── main/
        ├── shared/          # Memoire partagee
        │   ├── project/     # Architecture, roadmap
        │   ├── users/       # Profils utilisateurs
        │   ├── decisions/   # Decisions collectives
        │   └── events/      # Evenements inter-agents
        └── archive/         # Anciennes memoires
```

### Regles d'acces

| Zone | Permissions | Usage |
|------|-------------|-------|
| `memory/agents/<moi>/` | **RW** (Lecture/Ecriture) | Ma memoire privee |
| `memory/agents/<autre>/` | **R** (Lecture seule) | Consulter autres agents |
| `memory/shared/` | **RW** (Tous) | Collaboration |
| `memory/archive/` | **R** | Historique |

---

## Commandes Git Essentielles

### Verifier le statut

```bash
# Statut de la config
git -C ~/.openclaw status

# Statut de la memoire/workspace
git -C ~/.openclaw/workspace status

# Ou utiliser le script:
~/git-memory-status.sh
```

### Committer manuellement

```bash
# Config
cd ~/.openclaw
git add -A
git commit -m "feat(config): Description du changement"

# Memoire
cd ~/.openclaw/workspace
git add -A
git commit -m "feat(memory): Description du changement"
```

### Voir l'historique

```bash
# Derniers commits config
git -C ~/.openclaw log --oneline -10

# Derniers commits memoire
git -C ~/.openclaw/workspace log --oneline -10

# Qui a change quoi?
git -C ~/.openclaw/workspace log --format="%h %ai %an: %s" -10
```

### Comparer les versions

```bash
# Voir les differences depuis le dernier commit
git -C ~/.openclaw/workspace diff

# Voir un commit specifique
git -C ~/.openclaw/workspace show <commit-hash>

# Comparer deux commits
git -C ~/.openclaw/workspace diff <commit1>..<commit2>
```

---

## Rollback en Cas d'Erreur

### Utiliser le script de rollback

```bash
# Lister les derniers commits (config)
~/git-rollback.sh --list config

# Lister les derniers commits (workspace/memoire)
~/git-rollback.sh --list workspace

# Rollback vers un commit specifique
~/git-rollback.sh --rollback <commit-hash> config
~/git-rollback.sh --rollback <commit-hash> workspace

# Mode interactif
~/git-rollback.sh
```

### Rollback manuel

```bash
# Annuler les changements non commites
git -C ~/.openclaw/workspace checkout -- .

# Revenir a un commit precedent (garde l'historique)
git -C ~/.openclaw/workspace revert HEAD

# Revenir a un commit specifique (ATTENTION: perd l'historique)
git -C ~/.openclaw/workspace reset --hard <commit-hash>
```

---

## Commits Automatiques

### Hook sur /new et /reset

Un hook est configure pour committer automatiquement quand tu utilises `/new` ou `/reset`.

Le hook `git-memory-commit` :
- Detecte les changements dans config et workspace
- Cree un commit avec timestamp et contexte
- Format: `auto(<timestamp>): Session <action>`

### Watcher inotify (optionnel)

Un service surveille les fichiers et commit automatiquement :

```bash
# Verifier le statut du watcher
systemctl status openclaw-git-watcher

# Activer/desactiver
sudo systemctl enable openclaw-git-watcher
sudo systemctl disable openclaw-git-watcher

# Voir les logs
journalctl -u openclaw-git-watcher -f
```

---

## Communication Inter-Agents

### Ecrire dans la memoire partagee

```bash
# Creer un fichier d'evenement
cat > memory/shared/events/$(date +%s)-discovery.json <<EOF
{
  "timestamp": "$(date -Iseconds)",
  "agent": "main",
  "type": "discovery",
  "summary": "Decouverte importante",
  "ref": "memory/shared/users/alice.md"
}
EOF

git add memory/shared/events/
git commit -m "event(main): Nouvelle decouverte"
```

### Lire la memoire d'un autre agent

```bash
# Lire le journal d'un autre agent
cat memory/agents/agent-2/journal/latest.md

# Voir quand ca a ete modifie
git log -1 --format="%ai %an: %s" memory/agents/agent-2/
```

---

## Bonnes Pratiques

1. **Commits frequents, petits changements** - Moins de risque de perte
2. **Messages de commit descriptifs** - Facilite le rollback
3. **Ne jamais committer de secrets** - Utiliser le fichier `env` (ignore par git)
4. **Pull avant ecriture (si remote)** - Evite les conflits
5. **Zone d'ecriture unique par agent** - Evite les conflits multi-agent

---

## Cheat Sheet

```bash
# === STATUT ===
~/git-memory-status.sh              # Vue d'ensemble
git -C ~/.openclaw status           # Config
git -C ~/.openclaw/workspace status # Memoire

# === HISTORIQUE ===
git -C ~/.openclaw/workspace log --oneline -10
git -C ~/.openclaw/workspace blame <fichier>

# === ROLLBACK ===
~/git-rollback.sh                   # Mode interactif
~/git-rollback.sh --list workspace  # Lister commits
~/git-rollback.sh --rollback <hash> workspace

# === COMMIT MANUEL ===
cd ~/.openclaw/workspace && git add -A && git commit -m "message"

# === DIFFSFERENCES ===
git -C ~/.openclaw/workspace diff
git -C ~/.openclaw/workspace show HEAD

# === WATCHER ===
systemctl status openclaw-git-watcher
journalctl -u openclaw-git-watcher -f
```
GITMEMORY

    run_cmd chown "${OPENCLAW_USER}:${OPENCLAW_USER}" "$guide_file"
    log_success "GIT_MEMORY.md guide created"
}

setup_git_memory_hook() {
    local user_home
    user_home=$(eval echo ~"${OPENCLAW_USER}")
    local hooks_dir="${user_home}/.openclaw/hooks"
    local hook_dir="${hooks_dir}/git-memory-commit"

    if [[ -d "$hook_dir" ]]; then
        log_info "git-memory-commit hook already exists. Skipping."
        return 0
    fi

    log_info "Creating git-memory-commit hook..."
    run_cmd sudo -u "${OPENCLAW_USER}" mkdir -p "$hook_dir"

    # Create HOOK.md
    run_cmd tee "${hook_dir}/HOOK.md" > /dev/null <<'HOOKMD'
---
name: git-memory-commit
description: "Auto-commit config and memory changes on session events"
metadata: {"openclaw":{"emoji":"📝","events":["command:new","command:reset"],"requires":{"bins":["git"]}}}
---

# Git Memory Commit Hook

Automatically commits changes to the configuration and workspace repositories when session events occur (`/new`, `/reset`).

## What It Does

1. Checks for uncommitted changes in `~/.openclaw/` (config)
2. Checks for uncommitted changes in `~/.openclaw/workspace/` (memory)
3. Creates commits with descriptive messages including timestamp and action
4. Runs silently in the background

## Commit Format

```
auto(<YYYY-MM-DD HH:MM>): Session <action> - <context>
```

## Configuration

No configuration needed. The hook is enabled by default.

## Requirements

- Git must be installed
- Git repositories must be initialized (done by install.sh)
HOOKMD

    # Create handler.ts
    run_cmd tee "${hook_dir}/handler.ts" > /dev/null <<'HANDLERTS'
import type { HookHandler } from '../../src/hooks/hooks.js';
import { execSync } from 'child_process';
import { existsSync } from 'fs';
import { homedir } from 'os';
import { join } from 'path';

const handler: HookHandler = async (event) => {
  // Only trigger on 'new' or 'reset' commands
  if (event.type !== 'command') return;
  if (event.action !== 'new' && event.action !== 'reset') return;

  const home = homedir();
  const configDir = process.env.OPENCLAW_STATE_DIR || join(home, '.openclaw');
  const workspaceDir = process.env.OPENCLAW_WORKSPACE || join(configDir, 'workspace');

  const timestamp = new Date().toISOString().slice(0, 16).replace('T', ' ');
  const action = event.action;

  // Helper to run git commands
  const gitCommit = (dir: string, type: string) => {
    if (!existsSync(join(dir, '.git'))) return false;

    try {
      // Check if there are changes
      const status = execSync('git status --porcelain', { cwd: dir, encoding: 'utf8' });
      if (!status.trim()) return false;

      // Stage and commit
      execSync('git add -A', { cwd: dir });
      const message = `auto(${timestamp}): Session ${action} - ${type} snapshot`;
      execSync(`git commit -m "${message}"`, { cwd: dir });
      return true;
    } catch (e) {
      // Silently fail - don't interrupt the user
      console.error(`[git-memory-commit] Error committing ${type}:`, e);
      return false;
    }
  };

  // Commit config changes
  const configCommitted = gitCommit(configDir, 'config');

  // Commit workspace/memory changes
  const workspaceCommitted = gitCommit(workspaceDir, 'memory');

  // Optional: notify user (silent by default)
  if (configCommitted || workspaceCommitted) {
    const parts = [];
    if (configCommitted) parts.push('config');
    if (workspaceCommitted) parts.push('memory');
    // Uncomment to notify user:
    // event.messages.push(`📝 Git commit: ${parts.join(' + ')}`);
  }
};

export default handler;
HANDLERTS

    run_cmd chown -R "${OPENCLAW_USER}:${OPENCLAW_USER}" "$hook_dir"
    log_success "git-memory-commit hook created"

    # Enable the hook
    log_info "Enabling git-memory-commit hook..."
    run_cmd sudo -u "${OPENCLAW_USER}" bash -c "openclaw hooks enable git-memory-commit 2>/dev/null || true"
}

setup_git_rollback_script() {
    local user_home
    user_home=$(eval echo ~"${OPENCLAW_USER}")
    local script_path="${user_home}/git-rollback.sh"

    if [[ -f "$script_path" ]]; then
        log_info "git-rollback.sh already exists. Skipping."
        return 0
    fi

    log_info "Creating git-rollback.sh script..."
    run_cmd tee "$script_path" > /dev/null <<'ROLLBACK'
#!/bin/bash
# =============================================================================
# OpenClaw Git Rollback Script
# =============================================================================
# Safely rollback configuration or memory to a previous Git commit.
#
# Usage:
#   ./git-rollback.sh                           # Interactive mode
#   ./git-rollback.sh --list config             # List config commits
#   ./git-rollback.sh --list workspace          # List workspace commits
#   ./git-rollback.sh --rollback <hash> config  # Rollback config
#   ./git-rollback.sh --rollback <hash> workspace # Rollback workspace
#   ./git-rollback.sh --diff <hash> config      # Show diff
# =============================================================================
set -euo pipefail

# Colors
BOLD='\033[1m'
GREEN='\033[38;2;47;191;113m'
YELLOW='\033[38;2;255;176;32m'
RED='\033[38;2;226;61;45m'
CYAN='\033[38;2;0;200;200m'
NC='\033[0m'

# Directories
OPENCLAW_DIR="${OPENCLAW_STATE_DIR:-$HOME/.openclaw}"
WORKSPACE_DIR="${OPENCLAW_WORKSPACE:-$OPENCLAW_DIR/workspace}"

get_repo_dir() {
    local target="$1"
    case "$target" in
        config) echo "$OPENCLAW_DIR" ;;
        workspace|memory) echo "$WORKSPACE_DIR" ;;
        *) echo ""; return 1 ;;
    esac
}

list_commits() {
    local target="$1"
    local count="${2:-15}"
    local repo_dir
    repo_dir=$(get_repo_dir "$target")

    if [[ -z "$repo_dir" || ! -d "$repo_dir/.git" ]]; then
        echo -e "${RED}Error: Invalid target or Git not initialized for '$target'${NC}"
        return 1
    fi

    echo ""
    echo -e "${BOLD}${CYAN}Last $count commits for $target ($repo_dir):${NC}"
    echo ""
    git -C "$repo_dir" log --oneline --decorate -n "$count" --format="%C(yellow)%h%C(reset) %C(cyan)%ad%C(reset) %s" --date=short
    echo ""
}

show_diff() {
    local commit="$1"
    local target="$2"
    local repo_dir
    repo_dir=$(get_repo_dir "$target")

    if [[ -z "$repo_dir" || ! -d "$repo_dir/.git" ]]; then
        echo -e "${RED}Error: Invalid target or Git not initialized${NC}"
        return 1
    fi

    echo ""
    echo -e "${BOLD}${CYAN}Changes in commit $commit:${NC}"
    echo ""
    git -C "$repo_dir" show "$commit" --stat
    echo ""
    git -C "$repo_dir" show "$commit" --no-stat
}

do_rollback() {
    local commit="$1"
    local target="$2"
    local repo_dir
    repo_dir=$(get_repo_dir "$target")

    if [[ -z "$repo_dir" || ! -d "$repo_dir/.git" ]]; then
        echo -e "${RED}Error: Invalid target or Git not initialized${NC}"
        return 1
    fi

    # Verify commit exists
    if ! git -C "$repo_dir" rev-parse --verify "$commit" >/dev/null 2>&1; then
        echo -e "${RED}Error: Commit '$commit' not found${NC}"
        return 1
    fi

    echo ""
    echo -e "${YELLOW}WARNING: This will rollback $target to commit $commit${NC}"
    echo ""

    # Show what will change
    echo -e "${BOLD}Files that will be restored:${NC}"
    git -C "$repo_dir" diff --stat "$commit"..HEAD
    echo ""

    # Confirm
    echo -en "${YELLOW}Proceed with rollback? [y/N]: ${NC}"
    read -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        echo -e "${CYAN}Rollback cancelled.${NC}"
        return 0
    fi

    # Create safety branch
    local backup_branch="backup-$(date +%Y%m%d-%H%M%S)"
    echo -e "${CYAN}Creating backup branch: $backup_branch${NC}"
    git -C "$repo_dir" branch "$backup_branch"

    # Perform rollback
    echo -e "${CYAN}Rolling back to $commit...${NC}"
    git -C "$repo_dir" checkout "$commit" -- .
    git -C "$repo_dir" add -A
    git -C "$repo_dir" commit -m "rollback: Reverted to $commit (backup: $backup_branch)"

    echo ""
    echo -e "${GREEN}Rollback complete!${NC}"
    echo -e "Backup branch created: ${CYAN}$backup_branch${NC}"
    echo -e "To undo this rollback: ${CYAN}git -C $repo_dir checkout $backup_branch -- .${NC}"
    echo ""

    # Restart gateway if config changed
    if [[ "$target" == "config" ]]; then
        echo -e "${YELLOW}Config changed. You may need to restart the gateway:${NC}"
        echo -e "  ${CYAN}sudo systemctl restart openclaw-gateway${NC}"
    fi
}

interactive_mode() {
    echo ""
    echo -e "${BOLD}${CYAN}=====================================${NC}"
    echo -e "${BOLD}${CYAN}  OpenClaw Git Rollback Tool${NC}"
    echo -e "${BOLD}${CYAN}=====================================${NC}"
    echo ""

    # Select target
    echo -e "${BOLD}Select target:${NC}"
    echo "  1) config    - OpenClaw configuration (~/.openclaw/)"
    echo "  2) workspace - Memory and workspace (~/.openclaw/workspace/)"
    echo ""
    echo -en "${CYAN}Choice [1-2]: ${NC}"
    read -r choice

    local target=""
    case "$choice" in
        1) target="config" ;;
        2) target="workspace" ;;
        *)
            echo -e "${RED}Invalid choice${NC}"
            exit 1
            ;;
    esac

    # List commits
    list_commits "$target" 15

    # Ask for action
    echo -e "${BOLD}Actions:${NC}"
    echo "  1) Rollback to a commit"
    echo "  2) View diff of a commit"
    echo "  3) Exit"
    echo ""
    echo -en "${CYAN}Choice [1-3]: ${NC}"
    read -r action

    case "$action" in
        1)
            echo -en "${CYAN}Enter commit hash: ${NC}"
            read -r commit
            do_rollback "$commit" "$target"
            ;;
        2)
            echo -en "${CYAN}Enter commit hash: ${NC}"
            read -r commit
            show_diff "$commit" "$target"
            ;;
        3)
            echo "Bye!"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid choice${NC}"
            exit 1
            ;;
    esac
}

show_help() {
    cat <<'HELP'

  OpenClaw Git Rollback Tool

  Usage:
    ./git-rollback.sh                           # Interactive mode
    ./git-rollback.sh --list <target>           # List commits
    ./git-rollback.sh --rollback <hash> <target># Rollback to commit
    ./git-rollback.sh --diff <hash> <target>    # Show commit diff

  Targets:
    config      ~/.openclaw/ (configuration)
    workspace   ~/.openclaw/workspace/ (memory)

  Examples:
    ./git-rollback.sh --list config
    ./git-rollback.sh --list workspace
    ./git-rollback.sh --rollback abc123 config
    ./git-rollback.sh --diff abc123 workspace

HELP
}

# Main
case "${1:-}" in
    --list)
        list_commits "${2:-config}" "${3:-15}"
        ;;
    --rollback)
        if [[ -z "${2:-}" || -z "${3:-}" ]]; then
            echo -e "${RED}Usage: ./git-rollback.sh --rollback <hash> <target>${NC}"
            exit 1
        fi
        do_rollback "$2" "$3"
        ;;
    --diff)
        if [[ -z "${2:-}" || -z "${3:-}" ]]; then
            echo -e "${RED}Usage: ./git-rollback.sh --diff <hash> <target>${NC}"
            exit 1
        fi
        show_diff "$2" "$3"
        ;;
    --help|-h)
        show_help
        ;;
    "")
        interactive_mode
        ;;
    *)
        echo -e "${RED}Unknown option: $1${NC}"
        show_help
        exit 1
        ;;
esac
ROLLBACK

    run_cmd chown "${OPENCLAW_USER}:${OPENCLAW_USER}" "$script_path"
    run_cmd chmod 755 "$script_path"
    log_success "git-rollback.sh created"
}

setup_git_status_script() {
    local user_home
    user_home=$(eval echo ~"${OPENCLAW_USER}")
    local script_path="${user_home}/git-memory-status.sh"

    if [[ -f "$script_path" ]]; then
        log_info "git-memory-status.sh already exists. Skipping."
        return 0
    fi

    log_info "Creating git-memory-status.sh script..."
    run_cmd tee "$script_path" > /dev/null <<'GITSTATUS'
#!/bin/bash
# =============================================================================
# OpenClaw Git Memory Status
# =============================================================================
# Display Git status for both config and workspace repositories.
# =============================================================================

# Colors
BOLD='\033[1m'
GREEN='\033[38;2;47;191;113m'
YELLOW='\033[38;2;255;176;32m'
RED='\033[38;2;226;61;45m'
CYAN='\033[38;2;0;200;200m'
MUTED='\033[38;2;139;127;119m'
NC='\033[0m'

OPENCLAW_DIR="${OPENCLAW_STATE_DIR:-$HOME/.openclaw}"
WORKSPACE_DIR="${OPENCLAW_WORKSPACE:-$OPENCLAW_DIR/workspace}"

echo ""
echo -e "${BOLD}${CYAN}========================================${NC}"
echo -e "${BOLD}${CYAN}  OpenClaw Git Memory Status${NC}"
echo -e "${BOLD}${CYAN}========================================${NC}"
echo ""

# === Config Repository ===
echo -e "${BOLD}CONFIG${NC} (${MUTED}${OPENCLAW_DIR}${NC})"
echo -e "${MUTED}────────────────────────────────────────${NC}"

if [[ -d "$OPENCLAW_DIR/.git" ]]; then
    cd "$OPENCLAW_DIR"

    # Status
    changes=$(git status --porcelain 2>/dev/null | wc -l)
    if [[ "$changes" -eq 0 ]]; then
        echo -e "  Status: ${GREEN}Clean${NC}"
    else
        echo -e "  Status: ${YELLOW}$changes uncommitted change(s)${NC}"
        git status --porcelain 2>/dev/null | head -5 | while read -r line; do
            echo -e "    ${MUTED}$line${NC}"
        done
        if [[ "$changes" -gt 5 ]]; then
            echo -e "    ${MUTED}... and $((changes - 5)) more${NC}"
        fi
    fi

    # Last commit
    echo -e "  Last commit:"
    git log -1 --format="    %C(yellow)%h%C(reset) %C(cyan)%ad%C(reset) %s" --date=short 2>/dev/null || echo "    (none)"

    # Total commits
    total=$(git rev-list --count HEAD 2>/dev/null || echo "0")
    echo -e "  Total commits: ${CYAN}$total${NC}"
else
    echo -e "  ${RED}Git not initialized${NC}"
fi

echo ""

# === Workspace Repository ===
echo -e "${BOLD}WORKSPACE/MEMORY${NC} (${MUTED}${WORKSPACE_DIR}${NC})"
echo -e "${MUTED}────────────────────────────────────────${NC}"

if [[ -d "$WORKSPACE_DIR/.git" ]]; then
    cd "$WORKSPACE_DIR"

    # Status
    changes=$(git status --porcelain 2>/dev/null | wc -l)
    if [[ "$changes" -eq 0 ]]; then
        echo -e "  Status: ${GREEN}Clean${NC}"
    else
        echo -e "  Status: ${YELLOW}$changes uncommitted change(s)${NC}"
        git status --porcelain 2>/dev/null | head -5 | while read -r line; do
            echo -e "    ${MUTED}$line${NC}"
        done
        if [[ "$changes" -gt 5 ]]; then
            echo -e "    ${MUTED}... and $((changes - 5)) more${NC}"
        fi
    fi

    # Last commit
    echo -e "  Last commit:"
    git log -1 --format="    %C(yellow)%h%C(reset) %C(cyan)%ad%C(reset) %s" --date=short 2>/dev/null || echo "    (none)"

    # Total commits
    total=$(git rev-list --count HEAD 2>/dev/null || echo "0")
    echo -e "  Total commits: ${CYAN}$total${NC}"

    # Recent activity
    echo -e "  Recent activity (last 5):"
    git log --oneline -5 --format="    %C(yellow)%h%C(reset) %s" 2>/dev/null || echo "    (none)"
else
    echo -e "  ${RED}Git not initialized${NC}"
fi

echo ""

# === Watcher Service ===
echo -e "${BOLD}GIT WATCHER SERVICE${NC}"
echo -e "${MUTED}────────────────────────────────────────${NC}"
if systemctl is-active openclaw-git-watcher &>/dev/null; then
    echo -e "  Status: ${GREEN}Running${NC}"
else
    if systemctl is-enabled openclaw-git-watcher &>/dev/null 2>&1; then
        echo -e "  Status: ${YELLOW}Stopped (enabled)${NC}"
    else
        echo -e "  Status: ${MUTED}Disabled${NC}"
    fi
fi

echo ""
echo -e "${MUTED}Commands:${NC}"
echo -e "  ${CYAN}~/git-rollback.sh${NC}          - Rollback to previous version"
echo -e "  ${CYAN}~/git-rollback.sh --list${NC}   - List recent commits"
echo ""
GITSTATUS

    run_cmd chown "${OPENCLAW_USER}:${OPENCLAW_USER}" "$script_path"
    run_cmd chmod 755 "$script_path"
    log_success "git-memory-status.sh created"
}

setup_git_watcher_service() {
    local user_home
    user_home=$(eval echo ~"${OPENCLAW_USER}")
    local service_file="/etc/systemd/system/openclaw-git-watcher.service"
    local script_path="${user_home}/git-auto-commit.sh"

    if [[ -f "$service_file" ]]; then
        log_info "Git watcher service already exists. Skipping."
        return 0
    fi

    log_info "Creating Git auto-commit watcher..."

    # Create the watcher script
    run_cmd tee "$script_path" > /dev/null <<'WATCHER'
#!/bin/bash
# =============================================================================
# OpenClaw Git Auto-Commit Watcher
# =============================================================================
# Watches for file changes and commits automatically with debounce.
# =============================================================================
set -euo pipefail

OPENCLAW_DIR="${OPENCLAW_STATE_DIR:-$HOME/.openclaw}"
WORKSPACE_DIR="${OPENCLAW_WORKSPACE:-$OPENCLAW_DIR/workspace}"
DEBOUNCE_SECONDS=30
LAST_COMMIT_CONFIG=0
LAST_COMMIT_WORKSPACE=0

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

commit_if_changes() {
    local dir="$1"
    local type="$2"
    local last_var="$3"
    local now
    now=$(date +%s)

    # Check debounce
    local last_commit=${!last_var}
    if (( now - last_commit < DEBOUNCE_SECONDS )); then
        return 0
    fi

    # Check if git repo exists
    if [[ ! -d "$dir/.git" ]]; then
        return 0
    fi

    # Check for changes
    cd "$dir"
    local changes
    changes=$(git status --porcelain 2>/dev/null | wc -l)
    if [[ "$changes" -eq 0 ]]; then
        return 0
    fi

    # Commit
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M')
    git add -A
    git commit -m "auto(${timestamp}): File change detected - ${type}" >/dev/null 2>&1 || true

    log "Committed $changes change(s) to $type"

    # Update last commit time
    eval "$last_var=$now"
}

log "Git watcher started"
log "Watching: $OPENCLAW_DIR (config)"
log "Watching: $WORKSPACE_DIR (workspace)"
log "Debounce: ${DEBOUNCE_SECONDS}s"

# Watch both directories
inotifywait -m -r \
    --exclude '(\.git|node_modules|\.cache|\.swp|\.tmp)' \
    -e modify,create,delete,move \
    "$OPENCLAW_DIR" "$WORKSPACE_DIR" 2>/dev/null |
while read -r directory event filename; do
    # Skip .git directory events
    if [[ "$directory" == *".git"* ]]; then
        continue
    fi

    # Determine which repo changed
    if [[ "$directory" == "$WORKSPACE_DIR"* ]]; then
        commit_if_changes "$WORKSPACE_DIR" "workspace" "LAST_COMMIT_WORKSPACE"
    else
        commit_if_changes "$OPENCLAW_DIR" "config" "LAST_COMMIT_CONFIG"
    fi
done
WATCHER

    run_cmd chown "${OPENCLAW_USER}:${OPENCLAW_USER}" "$script_path"
    run_cmd chmod 755 "$script_path"

    # Create systemd service
    run_cmd tee "$service_file" > /dev/null <<EOF
[Unit]
Description=OpenClaw Git Auto-Commit Watcher
After=network.target openclaw-gateway.service

[Service]
Type=simple
User=${OPENCLAW_USER}
Group=${OPENCLAW_USER}
Environment="OPENCLAW_STATE_DIR=${user_home}/.openclaw"
Environment="OPENCLAW_WORKSPACE=${user_home}/.openclaw/workspace"
ExecStart=${script_path}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    run_cmd systemctl daemon-reload
    run_cmd systemctl enable openclaw-git-watcher
    run_cmd systemctl start openclaw-git-watcher
    log_success "Git watcher service created and started"
}

setup_docker_cleanup() {
    local cron_file="/etc/cron.d/openclaw-docker-cleanup"
    if [[ -f "$cron_file" ]]; then
        log_info "Docker cleanup cron already exists. Skipping."
        return 0
    fi

    log_info "Configuring weekly Docker cleanup..."
    run_cmd tee "$cron_file" > /dev/null <<'EOF'
# Docker cleanup - Sunday 3 AM
0 3 * * 0 root docker system prune -af --filter "until=168h" >> /var/log/docker-cleanup.log 2>&1
EOF

    log_success "Weekly Docker cleanup configured (Sunday 3 AM)"
}

setup_security_check_script() {
    local user_home
    user_home=$(eval echo ~"${OPENCLAW_USER}")
    local script_path="${user_home}/security-check.sh"

    if [[ -f "$script_path" ]]; then
        log_info "Security check script already exists. Skipping."
        return 0
    fi

    log_info "Creating security check script..."
    run_cmd tee "$script_path" > /dev/null <<'SECCHECK'
#!/bin/bash
# OpenClaw VPS Security Status
# Usage: sudo ./security-check.sh

echo ""
echo "========================================"
echo "  OpenClaw VPS Security Status"
echo "========================================"
echo ""

echo "--- UFW Firewall ---"
ufw status verbose 2>/dev/null || echo "  UFW not available"
echo ""

echo "--- CrowdSec Alerts (24h) ---"
cscli alerts list --since 24h 2>/dev/null || echo "  CrowdSec not available"
echo ""

echo "--- CrowdSec Active Decisions ---"
cscli decisions list 2>/dev/null || echo "  CrowdSec not available"
echo ""

echo "--- fail2ban Status ---"
fail2ban-client status sshd 2>/dev/null || echo "  fail2ban not available"
echo ""

echo "--- AIDE Last Check ---"
tail -5 /var/log/aide-check.log 2>/dev/null || echo "  No AIDE check yet"
echo ""

echo "--- Failed SSH Attempts (24h) ---"
journalctl -u sshd --since "24 hours ago" 2>/dev/null | grep -c "Failed password\|Invalid user" || echo "  0"
echo ""

echo "--- OpenClaw Gateway ---"
systemctl status openclaw-gateway --no-pager 2>/dev/null || echo "  Service not found"
echo ""

echo "--- Docker Sandbox Containers ---"
docker ps --filter label=openclaw.managed=true --format "table {{.Names}}\t{{.Status}}\t{{.Image}}" 2>/dev/null || echo "  No sandboxes running"
echo ""

echo "--- SearXNG ---"
docker ps --filter name=searxng --format "table {{.Names}}\t{{.Status}}\t{{.Image}}" 2>/dev/null || echo "  SearXNG not running"
echo ""

echo "--- Pending Updates ---"
apt list --upgradable 2>/dev/null | tail -n +2 | wc -l | xargs -I{} echo "  {} packages pending"
echo ""

echo "--- Disk Usage ---"
df -h / | awk 'NR==2 {printf "  Used: %s / %s (%s)\n", $3, $2, $5}'
echo ""

echo "========================================"
SECCHECK

    run_cmd chown "${OPENCLAW_USER}:${OPENCLAW_USER}" "$script_path"
    run_cmd chmod 755 "$script_path"
    log_success "Security check script created: ${script_path}"
}

setup_logrotate() {
    local config="/etc/logrotate.d/openclaw"
    if [[ -f "$config" ]]; then
        log_info "Logrotate already configured. Skipping."
        return 0
    fi

    log_info "Configuring log rotation..."
    run_cmd tee "$config" > /dev/null <<'EOF'
/var/log/openclaw-*.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
}

/var/log/docker-cleanup.log {
    monthly
    rotate 3
    compress
    missingok
    notifempty
}
EOF

    log_success "Log rotation configured"
}

verify_services() {
    log_info "Verifying services..."
    local all_ok=true

    # OpenClaw Gateway
    if systemctl is-active openclaw-gateway &>/dev/null; then
        log_success "OpenClaw Gateway: running"
    else
        log_warn "OpenClaw Gateway: not running"
        log_info "Checking logs: journalctl -u openclaw-gateway -n 20"
        journalctl -u openclaw-gateway -n 10 --no-pager 2>/dev/null || true
        all_ok=false
    fi

    # Caddy
    if systemctl is-active caddy &>/dev/null; then
        log_success "Caddy reverse proxy: running"
    else
        log_warn "Caddy: not running"
        all_ok=false
    fi

    # Docker
    if systemctl is-active docker &>/dev/null; then
        log_success "Docker Engine: running"
    else
        log_warn "Docker: not running"
        all_ok=false
    fi

    # SearXNG
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^searxng$"; then
        log_success "SearXNG: running"
    else
        log_warn "SearXNG: not running"
        all_ok=false
    fi

    # CrowdSec
    if systemctl is-active crowdsec &>/dev/null; then
        log_success "CrowdSec: running"
    else
        log_warn "CrowdSec: not running"
        all_ok=false
    fi

    # fail2ban
    if systemctl is-active fail2ban &>/dev/null; then
        log_success "fail2ban: running"
    else
        log_warn "fail2ban: not running"
        all_ok=false
    fi

    # UFW
    if ufw status 2>/dev/null | grep -q "Status: active"; then
        log_success "UFW Firewall: active"
    else
        log_warn "UFW: inactive"
        all_ok=false
    fi

    if $all_ok; then
        log_success "All services verified successfully"
    else
        log_warn "Some services need attention (see warnings above)"
    fi
}

display_summary() {
    local user_home
    user_home=$(eval echo ~"${OPENCLAW_USER}")

    local access_url=""
    if [[ -n "$DOMAIN" && -n "$EMAIL" ]]; then
        access_url="https://${DOMAIN}/?token=${GATEWAY_TOKEN}"
    elif [[ -n "$DOMAIN" ]]; then
        access_url="http://${DOMAIN}/?token=${GATEWAY_TOKEN}"
    else
        local server_ip
        server_ip=$(curl -s --max-time 5 https://ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
        access_url="http://${server_ip}/?token=${GATEWAY_TOKEN}"
    fi

    echo ""
    echo -e "${BOLD}${GREEN}=====================================================================${NC}"
    echo -e "${BOLD}${GREEN}  Installation OpenClaw terminee - VPS Securise (Natif)${NC}"
    echo -e "${BOLD}${GREEN}=====================================================================${NC}"
    echo ""
    echo -e "  ${BOLD}ACCES${NC}"
    echo -e "    URL:          ${CYAN}${access_url}${NC}"
    echo -e "    Token:        ${CYAN}${GATEWAY_TOKEN}${NC}"
    echo ""
    echo -e "  ${BOLD}SYSTEME${NC}"
    echo -e "    SSH User:     ${CYAN}${OPENCLAW_USER}${NC} (port ${SSH_PORT})"
    echo -e "    Gateway:      ${CYAN}systemd (openclaw-gateway.service)${NC}"
    echo -e "    Config:       ${CYAN}${user_home}/.openclaw/${NC}"
    echo -e "    Env vars:     ${CYAN}${user_home}/.openclaw/env${NC}"
    echo -e "    SearXNG:      ${CYAN}Docker (localhost:${SEARXNG_PORT})${NC}"
    echo -e "    Sandboxes:    ${CYAN}Docker (openclaw-sandbox:bookworm-slim)${NC}"
    echo ""
    echo -e "  ${BOLD}SECURITE ACTIVE${NC}"
    echo -e "    ${GREEN}[OK]${NC} UFW Firewall          (deny in + deny out)"
    echo -e "    ${GREEN}[OK]${NC} CrowdSec IPS          (intrusion collaborative)"
    echo -e "    ${GREEN}[OK]${NC} fail2ban               (ban SSH 24h)"
    echo -e "    ${GREEN}[OK]${NC} Kernel sysctl          (anti-spoofing, SYN flood)"
    echo -e "    ${GREEN}[OK]${NC} SSH hardened            (key-only, root off)"
    echo -e "    ${GREEN}[OK]${NC} AIDE                   (file integrity, daily 5 AM)"
    echo -e "    ${GREEN}[OK]${NC} Auditd                 (system audit journal)"
    echo -e "    ${GREEN}[OK]${NC} Unattended-upgrades    (auto security patches)"
    if [[ -n "$DOMAIN" && -n "$EMAIL" ]]; then
        echo -e "    ${GREEN}[OK]${NC} Caddy HTTPS            (TLS auto + security headers)"
    else
        echo -e "    ${YELLOW}[--]${NC} Caddy HTTP             (add domain for HTTPS)"
    fi
    echo -e "    ${GREEN}[OK]${NC} Systemd hardening      (NoNewPrivileges, ProtectSystem)"
    echo -e "    ${GREEN}[OK]${NC} Metadata blocked       (169.254.169.254)"
    echo -e "    ${GREEN}[OK]${NC} Git versioning         (config + memory auto-commit)"
    echo ""
    echo -e "  ${BOLD}COMMANDES UTILES${NC}"
    echo -e "    Statut securite :  ${CYAN}sudo ${user_home}/security-check.sh${NC}"
    echo -e "    Logs gateway :     ${CYAN}journalctl -u openclaw-gateway -f${NC}"
    echo -e "    Restart gateway :  ${CYAN}sudo systemctl restart openclaw-gateway${NC}"
    echo -e "    Backup manuel :    ${CYAN}${user_home}/backup.sh${NC}"
    echo -e "    Logs CrowdSec :    ${CYAN}sudo cscli alerts list${NC}"
    echo -e "    IPs bannies :      ${CYAN}sudo cscli decisions list${NC}"
    echo ""
    echo -e "  ${BOLD}GIT VERSIONING${NC}"
    echo -e "    Statut Git :       ${CYAN}${user_home}/git-memory-status.sh${NC}"
    echo -e "    Rollback :         ${CYAN}${user_home}/git-rollback.sh${NC}"
    echo -e "    Guide :            ${CYAN}${user_home}/.openclaw/workspace/GIT_MEMORY.md${NC}"
    echo -e "    Watcher logs :     ${CYAN}journalctl -u openclaw-git-watcher -f${NC}"
    echo ""
    echo -e "  ${BOLD}PROCHAINES ETAPES${NC}"
    echo -e "    1. Ouvrir l'URL ci-dessus dans le navigateur"
    echo -e "    2. Executer dans le terminal : ${CYAN}openclaw-approve${NC}"
    echo -e "    3. Executer : ${CYAN}openclaw onboard${NC}"
    echo -e "    4. Configurer les canaux (Telegram, WhatsApp)"
    echo ""
    echo -e "  ${BOLD}${YELLOW}RECOMMANDATION${NC}"
    echo -e "    Activer aussi le firewall Hetzner Cloud (console.hetzner.cloud)"
    echo -e "    avec les memes regles (SSH + 80 + 443) pour defense en profondeur."
    echo ""
    echo -e "${BOLD}${GREEN}=====================================================================${NC}"
    echo ""

    # Save summary to file for reference
    {
        echo "OpenClaw Installation Summary"
        echo "Date: $(date)"
        echo "URL: ${access_url}"
        echo "Token: ${GATEWAY_TOKEN}"
        echo "User: ${OPENCLAW_USER}"
        echo "SSH Port: ${SSH_PORT}"
        echo "Domain: ${DOMAIN:-none}"
        echo "Config: ${user_home}/.openclaw/"
    } > "${user_home}/install-summary.txt"
    chown "${OPENCLAW_USER}:${OPENCLAW_USER}" "${user_home}/install-summary.txt"
    chmod 600 "${user_home}/install-summary.txt"
}

# =============================================================================
# Main Execution
# =============================================================================
main() {
    parse_arguments "$@"

    if $DRY_RUN; then
        echo -e "${BOLD}${YELLOW}=== DRY RUN MODE === No changes will be made ===${NC}"
        echo ""
    fi

    preflight_checks
    interactive_prompts

    # Phase 1: System Preparation & Security
    log_step 1 "System Preparation & Security Hardening"
    update_system
    install_base_packages
    set_timezone
    configure_swap
    create_user
    harden_ssh
    setup_firewall
    setup_crowdsec
    setup_fail2ban
    harden_kernel
    setup_aide
    setup_auditd
    setup_unattended_upgrades

    # Phase 2: Docker (Sandboxes Only)
    log_step 2 "Docker Installation (Sandboxes Only)"
    install_docker
    configure_docker_daemon
    setup_searxng
    setup_sandbox_images

    # Phase 3: OpenClaw Native Installation
    log_step 3 "OpenClaw Native Installation"
    install_nodejs
    install_extra_tools
    install_openclaw
    configure_openclaw
    setup_systemd_service

    # Phase 4: Reverse Proxy
    log_step 4 "Caddy Reverse Proxy"
    install_caddy
    configure_caddy

    # Phase 5: Post-Installation
    log_step 5 "Post-Installation & Monitoring"
    setup_backup
    setup_git_versioning
    setup_docker_cleanup
    setup_security_check_script
    setup_logrotate
    verify_services
    display_summary
}

main "$@"
