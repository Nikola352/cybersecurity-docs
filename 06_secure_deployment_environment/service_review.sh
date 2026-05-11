#!/usr/bin/env bash
# =============================================================================
# security_audit.sh — Linux Security Auditor (LinPEAS-style)
# =============================================================================
# Checks: running services, SSH config, MySQL config, network exposure,
# sudo config, open ports, and more.
# =============================================================================

set -euo pipefail

# ── Colors & formatting ──────────────────────────────────────────────────────
RED='\033[0;31m';    BRED='\033[1;31m'
GREEN='\033[0;32m';  BGREEN='\033[1;32m'
YELLOW='\033[1;33m'; BYELLOW='\033[1;33m'
CYAN='\033[0;36m';   BCYAN='\033[1;36m'
BLUE='\033[0;34m'
BOLD='\033[1m';      RESET='\033[0m'
ORANGE='\033[38;5;208m'

banner() {
  echo -e "${BRED}"
  echo "  ╔══════════════════════════════════════════════════════╗"
  echo "  ║         LINUX SECURITY AUDIT SCRIPT v1.0            ║"
  echo "  ║   Checks SSH, MySQL, Services, Network & More       ║"
  echo "  ╚══════════════════════════════════════════════════════╝"
  echo -e "${RESET}"
}

section() { echo -e "\n${BCYAN}══════════════════════════════════════════${RESET}"; echo -e "${BCYAN}  ▶ $1${RESET}"; echo -e "${BCYAN}══════════════════════════════════════════${RESET}"; }
ok()      { echo -e "  ${BGREEN}[✔ OK  ]${RESET} $1"; }
warn()    { echo -e "  ${BYELLOW}[⚠ WARN]${RESET} $1"; }
vuln()    { echo -e "  ${BRED}[✘ VULN]${RESET} $1"; }
info()    { echo -e "  ${CYAN}[ℹ INFO]${RESET} $1"; }
detail()  { echo -e "        ${BLUE}↳${RESET} $1"; }

# ── Privilege check ──────────────────────────────────────────────────────────
check_sudo() {
  if [[ $EUID -ne 0 ]]; then
    echo -e "${BYELLOW}[*] This script requires root privileges for full auditing.${RESET}"
    echo -e "${BYELLOW}[*] Re-launching with sudo...${RESET}\n"
    exec sudo bash "$0" "$@"
  fi
}

check_sudo "$@"

banner
echo -e "  ${BOLD}Host:${RESET} $(hostname)   ${BOLD}Date:${RESET} $(date)"
echo -e "  ${BOLD}User:${RESET} $(whoami)     ${BOLD}Kernel:${RESET} $(uname -r)\n"

ISSUES=0
inc_issues() { ISSUES=$((ISSUES + 1)); }

# ── 1. RUNNING SERVICES (ps) ──────────────────────────────────────────────────
section "1. RUNNING SERVICES (ps)"
info "Top processes by CPU/memory:"
ps aux --sort=-%cpu 2>/dev/null | head -20 | awk '{printf "        %-10s %-6s %-6s %s\n",$1,$2,$3,$11}' || true

info "Interesting services detected:"
INTERESTING=(sshd mysql mysqld apache2 nginx php-fpm docker containerd cron atd postfix sendmail vsftpd telnet rpcbind nfs smbd nmbd)
for svc in "${INTERESTING[@]}"; do
  if pgrep -x "$svc" &>/dev/null; then
    warn "Running: ${BOLD}$svc${RESET} (PID: $(pgrep -x "$svc" | tr '\n' ' '))"
  fi
done

# ── 2. NETWORK CONNECTIONS & LISTENING SERVICES (lsof / ss) ──────────────────
section "2. NETWORK CONNECTIONS (lsof / ss)"
if command -v lsof &>/dev/null; then
  info "Services listening on network (lsof):"
  lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR>1 {printf "        %-15s %-7s %-25s %s\n",$1,$2,$9,$10}' || true
  echo ""
  info "Services listening on UDP:"
  lsof -nP -iUDP 2>/dev/null | awk 'NR>1 {printf "        %-15s %-7s %s\n",$1,$2,$9}' | head -20 || true
else
  warn "lsof not found — falling back to ss"
  ss -tulnp 2>/dev/null | head -30 || netstat -tulnp 2>/dev/null | head -30 || true
fi

# Check if MySQL is exposed externally
section "2a. MYSQL NETWORK EXPOSURE"
MYSQL_BIND=""
if [[ -f /etc/mysql/my.cnf ]]; then
  MYSQL_BIND=$(grep -i "bind-address" /etc/mysql/my.cnf 2>/dev/null | tail -1 | awk -F= '{print $2}' | tr -d ' ' || true)
fi
if [[ -f /etc/mysql/mysql.conf.d/mysqld.cnf ]]; then
  _b=$(grep -i "bind-address" /etc/mysql/mysql.conf.d/mysqld.cnf 2>/dev/null | tail -1 | awk -F= '{print $2}' | tr -d ' ' || true)
  [[ -n "$_b" ]] && MYSQL_BIND="$_b"
fi

if command -v lsof &>/dev/null; then
  MYSQL_LISTEN=$(lsof -nP -iTCP:3306 -sTCP:LISTEN 2>/dev/null | grep -v "^COMMAND" || true)
else
  MYSQL_LISTEN=$(ss -tlnp 2>/dev/null | grep ':3306' || true)
fi

if [[ -n "$MYSQL_LISTEN" ]]; then
  if echo "$MYSQL_LISTEN" | grep -qE '\*:3306|0\.0\.0\.0:3306'; then
    vuln "MySQL is listening on ALL interfaces (0.0.0.0:3306) — externally reachable!"
    detail "Fix: add 'bind-address = 127.0.0.1' to [mysqld] in /etc/mysql/my.cnf"
    detail "Then restart MySQL: systemctl restart mysql"
    inc_issues
  else
    ok "MySQL is bound to localhost only"
  fi
elif [[ "$MYSQL_BIND" == "127.0.0.1" ]]; then
  ok "MySQL bind-address = 127.0.0.1 (localhost only)"
elif [[ -n "$MYSQL_BIND" ]]; then
  warn "MySQL bind-address = $MYSQL_BIND — verify this is intentional"
fi

# ── 3. SSH CONFIGURATION ──────────────────────────────────────────────────────
section "3. SSH CONFIGURATION (/etc/ssh/sshd_config)"
SSH_CFG="/etc/ssh/sshd_config"
if [[ ! -f "$SSH_CFG" ]]; then
  warn "sshd_config not found at $SSH_CFG — SSH may not be installed"
else
  # PermitRootLogin
  ROOT_LOGIN=$(grep -i "^\s*PermitRootLogin" "$SSH_CFG" 2>/dev/null | awk '{print $2}' | tail -1 || true)
  if [[ -z "$ROOT_LOGIN" ]]; then
    vuln "PermitRootLogin is not explicitly set — defaults to 'yes' (allows root SSH login!)"
    detail "Fix: add 'PermitRootLogin no' to $SSH_CFG"
    inc_issues
  elif [[ "${ROOT_LOGIN,,}" == "yes" ]]; then
    vuln "PermitRootLogin = yes — root can SSH in directly!"
    detail "Fix: set 'PermitRootLogin no' in $SSH_CFG"
    inc_issues
  elif [[ "${ROOT_LOGIN,,}" == "without-password" || "${ROOT_LOGIN,,}" == "prohibit-password" ]]; then
    warn "PermitRootLogin = $ROOT_LOGIN — root can log in with key auth"
    detail "Consider setting to 'no' for maximum security"
  else
    ok "PermitRootLogin = $ROOT_LOGIN"
  fi

  # Protocol version
  PROTO=$(grep -i "^\s*Protocol" "$SSH_CFG" 2>/dev/null | awk '{print $2}' | tail -1 || true)
  if [[ -z "$PROTO" ]]; then
    warn "SSH Protocol not explicitly set — SSHv1 may be enabled on older systems"
    detail "Fix: add 'Protocol 2' to $SSH_CFG"
  elif [[ "$PROTO" == "2" ]]; then
    ok "Protocol = 2 (SSHv1 disabled)"
  else
    vuln "Protocol = $PROTO — SSHv1 may be in use! SSHv1 is cryptographically broken."
    detail "Fix: set 'Protocol 2' in $SSH_CFG"
    inc_issues
  fi

  # AllowTcpForwarding
  TCP_FWD=$(grep -i "^\s*AllowTcpForwarding" "$SSH_CFG" 2>/dev/null | awk '{print $2}' | tail -1 || true)
  if [[ -z "$TCP_FWD" ]]; then
    vuln "AllowTcpForwarding not set — defaults to 'yes' (tunneling enabled!)"
    detail "Fix: add 'AllowTcpForwarding no' to $SSH_CFG (if this is not a jump/bounce host)"
    inc_issues
  elif [[ "${TCP_FWD,,}" == "yes" ]]; then
    vuln "AllowTcpForwarding = yes — users can tunnel through this host!"
    detail "Fix: set 'AllowTcpForwarding no' in $SSH_CFG"
    inc_issues
  else
    ok "AllowTcpForwarding = $TCP_FWD"
  fi

  # SSH Port
  SSH_PORT=$(grep -i "^\s*Port" "$SSH_CFG" 2>/dev/null | awk '{print $2}' | tail -1 || true)
  SSH_PORT="${SSH_PORT:-22}"
  if [[ "$SSH_PORT" == "22" ]]; then
    warn "SSH is on default port 22 — easily found by automated scanners"
    detail "Consider changing 'Port' in $SSH_CFG and updating your firewall"
  else
    ok "SSH running on non-default port: $SSH_PORT (good against scanners)"
  fi

  # PasswordAuthentication
  PASS_AUTH=$(grep -i "^\s*PasswordAuthentication" "$SSH_CFG" 2>/dev/null | awk '{print $2}' | tail -1 || true)
  if [[ "${PASS_AUTH,,}" == "yes" || -z "$PASS_AUTH" ]]; then
    warn "PasswordAuthentication = ${PASS_AUTH:-yes (default)} — brute-force attacks possible"
    detail "Consider 'PasswordAuthentication no' and using key-based auth only"
  else
    ok "PasswordAuthentication = $PASS_AUTH"
  fi

  # X11Forwarding
  X11=$(grep -i "^\s*X11Forwarding" "$SSH_CFG" 2>/dev/null | awk '{print $2}' | tail -1 || true)
  if [[ "${X11,,}" == "yes" ]]; then
    warn "X11Forwarding = yes — may expose local X11 display"
    detail "Set 'X11Forwarding no' unless needed"
  fi

  # MaxAuthTries
  MAX_TRIES=$(grep -i "^\s*MaxAuthTries" "$SSH_CFG" 2>/dev/null | awk '{print $2}' | tail -1 || true)
  if [[ -z "$MAX_TRIES" || "$MAX_TRIES" -gt 4 ]]; then
    warn "MaxAuthTries = ${MAX_TRIES:-6 (default)} — consider lowering to 3 or 4"
  else
    ok "MaxAuthTries = $MAX_TRIES"
  fi

  echo ""
  info "After making any SSH config changes, restart the service:"
  detail "systemctl restart sshd   (or: service ssh restart)"
fi

# ── 4. MYSQL CONFIGURATION ────────────────────────────────────────────────────
section "4. MYSQL CONFIGURATION"
MYSQL_CNF="/etc/mysql/my.cnf"
if [[ ! -f "$MYSQL_CNF" ]] && [[ -f /etc/mysql/mysql.conf.d/mysqld.cnf ]]; then
  MYSQL_CNF="/etc/mysql/mysql.conf.d/mysqld.cnf"
fi

if [[ -f "$MYSQL_CNF" ]]; then
  info "MySQL config: $MYSQL_CNF"

  # Check for no-password root access
  if command -v mysql &>/dev/null; then
    if mysql -u root --connect-timeout=3 -e "SELECT 1;" &>/dev/null 2>&1; then
      vuln "MySQL root login requires NO password — database fully exposed!"
      detail "Fix: ALTER USER 'root'@'localhost' IDENTIFIED BY 'StrongPassword';"
      inc_issues
    else
      ok "MySQL root requires a password"
    fi
  fi

  # Check for anonymous users hint via MYD file
  if [[ -f /var/lib/mysql/mysql/user.MYD ]]; then
    warn "MySQL user table binary found at /var/lib/mysql/mysql/user.MYD"
    detail "Password hashes may be extractable with: strings /var/lib/mysql/mysql/user.MYD"
  fi

  # bind-address check (already done above but mention config line)
  if grep -q "bind-address" "$MYSQL_CNF" 2>/dev/null; then
    info "bind-address setting found in $MYSQL_CNF:"
    grep "bind-address" "$MYSQL_CNF" | while read -r line; do detail "$line"; done
  else
    warn "No bind-address found in $MYSQL_CNF — MySQL may listen on all interfaces"
    detail "Add 'bind-address = 127.0.0.1' under [mysqld] in $MYSQL_CNF"
  fi

  echo ""
  info "After making any MySQL config changes, restart the service:"
  detail "systemctl restart mysql   (or: service mysql restart)"
else
  info "MySQL config file not found — MySQL may not be installed or uses different path"
fi

# ── 5. SUDO CONFIGURATION ─────────────────────────────────────────────────────
section "5. SUDO CONFIGURATION"
if [[ -f /etc/sudoers ]]; then
  # Check for NOPASSWD
  if grep -qE "NOPASSWD" /etc/sudoers 2>/dev/null; then
    vuln "NOPASSWD entries found in /etc/sudoers — passwordless sudo possible!"
    grep -E "NOPASSWD" /etc/sudoers | while read -r line; do
      [[ "$line" =~ ^# ]] && continue
      detail "$line"
    done
    inc_issues
  else
    ok "No NOPASSWD entries in /etc/sudoers"
  fi
  # Check for ALL=(ALL) ALL
  if grep -qE "^\s*ALL\s*=\s*\(ALL\)" /etc/sudoers 2>/dev/null; then
    warn "Broad sudo access found (ALL=(ALL) ALL) — verify intended users only"
    grep -E "^\s*[^#].*ALL=\(ALL\)" /etc/sudoers | while read -r line; do detail "$line"; done
  fi
  # sudoers.d
  if [[ -d /etc/sudoers.d ]]; then
    info "Checking /etc/sudoers.d/ for NOPASSWD:"
    find /etc/sudoers.d/ -type f 2>/dev/null | while read -r f; do
      if grep -qE "NOPASSWD" "$f" 2>/dev/null; then
        vuln "NOPASSWD in $f:"
        grep -E "NOPASSWD" "$f" | while read -r line; do detail "$line"; done
        inc_issues
      fi
    done
  fi
else
  warn "/etc/sudoers not readable"
fi

# ── 6. WORLD-WRITABLE FILES & DIRECTORIES ─────────────────────────────────────
section "6. WORLD-WRITABLE FILES (sensitive paths)"
info "Scanning /etc, /tmp, /var for world-writable files..."
WW_FILES=$(find /etc /var/www /tmp /opt 2>/dev/null -maxdepth 4 -type f -perm -o+w \
  ! -path "*/proc/*" ! -path "*/sys/*" 2>/dev/null | head -20 || true)
if [[ -n "$WW_FILES" ]]; then
  vuln "World-writable files found:"
  echo "$WW_FILES" | while read -r f; do detail "$f"; done
  inc_issues
else
  ok "No world-writable files found in scanned paths"
fi

# ── 7. SUID / SGID BINARIES ───────────────────────────────────────────────────
section "7. SUID/SGID BINARIES"
info "Scanning for SUID binaries (these can be used for privilege escalation)..."
SUID_BINS=$(find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | sort)
KNOWN_SUID=(su sudo passwd mount umount ping newgrp chsh chfn gpasswd)
FLAGGED=false
while IFS= read -r bin; do
  bname=$(basename "$bin")
  is_known=false
  for k in "${KNOWN_SUID[@]}"; do [[ "$bname" == "$k" ]] && is_known=true && break; done
  if $is_known; then
    ok "Known SUID: $bin"
  else
    warn "Unusual SUID/SGID: $bin"
    FLAGGED=true
  fi
done <<< "$SUID_BINS"
if $FLAGGED; then
  detail "Review unusual SUID binaries — some may allow privilege escalation (GTFOBins)"
fi

# ── 8. CRON JOBS & CRON SCRIPT PERMISSIONS ───────────────────────────────────
section "8. CRON JOBS & CRON SCRIPT PERMISSIONS"
info "System crontabs:"
for f in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/*; do
  [[ -f "$f" ]] || continue
  echo -e "  ${BLUE}── $f ──${RESET}"
  grep -v "^#\|^$" "$f" 2>/dev/null | while read -r line; do detail "$line"; done
done

# Check permissions on scripts invoked by cron tasks.
# A world- or group-writable script run by root = instant privilege escalation.
info "Checking write permissions of scripts called by cron tasks:"
CRON_SCRIPTS_CHECKED=false
for f in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/*; do
  [[ -f "$f" ]] || continue
  while IFS= read -r cronline; do
    [[ "$cronline" =~ ^[[:space:]]*# ]] && continue
    [[ -z "$cronline" ]] && continue
    for token in $cronline; do
      [[ "$token" == /* ]] || continue
      [[ "$token" == /bin/sh   ]] && continue
      [[ "$token" == /bin/bash ]] && continue
      [[ "$token" == /usr/bin/env ]] && continue
      [[ -f "$token" ]] || continue
      CRON_SCRIPTS_CHECKED=true
      PERMS=$(stat -c "%a" "$token" 2>/dev/null || true)
      OWNER=$(stat -c "%U" "$token" 2>/dev/null || true)
      if [[ -n "$PERMS" ]]; then
        if (( (8#$PERMS & 8#002) != 0 )); then
          vuln "Cron script WORLD-WRITABLE — any user can hijack execution as ${OWNER}:"
          detail "File: $token  (perms: $PERMS, owner: $OWNER)"
          detail "Fix: chmod o-w \"$token\""
          inc_issues
        elif (( (8#$PERMS & 8#020) != 0 )); then
          warn "Cron script is group-writable:"
          detail "File: $token  (perms: $PERMS, owner: $OWNER)"
          detail "Verify group members cannot abuse this for privilege escalation"
        else
          ok "Cron script permissions OK: $token  ($PERMS / $OWNER)"
        fi
      fi
    done
  done < "$f"
done
$CRON_SCRIPTS_CHECKED || info "No absolute-path scripts found in cron entries"

# ── 9. OPEN PORTS FIREWALL SUMMARY ────────────────────────────────────────────
section "9. FIREWALL STATUS"
if command -v ufw &>/dev/null; then
  info "UFW status:"
  ufw status verbose 2>/dev/null | while read -r line; do detail "$line"; done
elif command -v iptables &>/dev/null; then
  info "iptables INPUT chain:"
  iptables -L INPUT -n --line-numbers 2>/dev/null | while read -r line; do detail "$line"; done
else
  warn "No firewall tool found (ufw/iptables)"
fi

# ── 10. PASSWORD POLICY ───────────────────────────────────────────────────────
section "10. PASSWORD POLICY & ACCOUNTS"
# Accounts with no password
info "Accounts with empty passwords:"
EMPTY_PASS=$(awk -F: '($2 == "" || $2 == "!!" ) {print $1}' /etc/shadow 2>/dev/null || true)
if [[ -n "$EMPTY_PASS" ]]; then
  vuln "Accounts with no/locked password:"
  echo "$EMPTY_PASS" | while read -r u; do detail "$u"; done
  inc_issues
else
  ok "No accounts with empty passwords"
fi

# UID 0 accounts other than root
info "Accounts with UID 0 (root-equivalent):"
UID0=$(awk -F: '($3 == 0) {print $1}' /etc/passwd 2>/dev/null || true)
if [[ $(echo "$UID0" | wc -l) -gt 1 ]]; then
  vuln "Multiple UID 0 accounts:"
  echo "$UID0" | while read -r u; do detail "$u"; done
  inc_issues
else
  ok "Only root has UID 0"
fi

# Password policy (login.defs)
if [[ -f /etc/login.defs ]]; then
  PASS_MAX=$(grep "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}' || true)
  PASS_MIN=$(grep "^PASS_MIN_LEN"  /etc/login.defs 2>/dev/null | awk '{print $2}' || true)
  info "Password policy (login.defs): MAX_DAYS=${PASS_MAX:-N/A}  MIN_LEN=${PASS_MIN:-N/A}"
  if [[ -n "$PASS_MAX" && "$PASS_MAX" -gt 90 ]]; then
    warn "PASS_MAX_DAYS = $PASS_MAX — consider 60-90 days"
  fi
fi

# ── 11. INSTALLED SERVICES / PACKAGES TO VERIFY ───────────────────────────────
section "11. NOTABLE INSTALLED SOFTWARE"
for pkg in telnet rsh-client rlogin ftp netcat ncat nmap wireshark tcpdump john hydra; do
  if command -v "$pkg" &>/dev/null; then
    warn "Potentially sensitive tool installed: ${BOLD}$pkg${RESET} ($(command -v "$pkg"))"
  fi
done

# ── 12. MYSQL DEEP-DIVE ───────────────────────────────────────────────────────
section "12. MYSQL DEEP-DIVE"

# debian-sys-maint credentials exposure
if [[ -f /etc/mysql/debian.cnf ]]; then
  warn "debian.cnf is readable — contains debian-sys-maint credentials!"
  detail "File: /etc/mysql/debian.cnf"
  detail "Anyone with root can read this and gain full DB access via the maintenance user"
  DEBIANCNF_PASS=$(grep -i "^password" /etc/mysql/debian.cnf 2>/dev/null | head -1 | awk -F= '{print $2}' | tr -d ' ' || true)
  if [[ -n "$DEBIANCNF_PASS" ]]; then
    detail "Password found in debian.cnf (redacted for safety — exists and is non-empty)"
  fi
fi

# Try connecting as root with no password
MYSQL_ROOT_NOPASS=false
if command -v mysql &>/dev/null; then
  if mysql -u root --connect-timeout=3 -e "SELECT 1;" &>/dev/null 2>&1; then
    MYSQL_ROOT_NOPASS=true
    vuln "MySQL root has NO password — connecting now to run security checks..."
    inc_issues

    # MySQL version
    MYSQL_VER=$(mysql -u root -e "SELECT @@version;" 2>/dev/null | tail -1 || true)
    info "MySQL version: ${BOLD}$MYSQL_VER${RESET}"
    detail "Search for known CVEs: https://www.cvedetails.com/product/13510/Oracle-Mysql.html"

    # List all users and password hashes
    info "MySQL users and password hashes:"
    mysql -u root -e "SELECT user, host, password FROM mysql.user;" 2>/dev/null | \
      while IFS=$'\t' read -r usr host pass; do
        if [[ "$usr" == "user" ]]; then continue; fi  # skip header
        if [[ -z "$pass" ]]; then
          vuln "User '${usr}'@'${host}' has NO password set!"
          inc_issues
        elif [[ ${#pass} -le 16 ]]; then
          warn "User '${usr}'@'${host}' uses OLD (weak) password hash: $pass"
          detail "Old algorithm is cryptographically weak — upgrade to new_password()"
        else
          ok "User '${usr}'@'${host}' uses new password hash (first 8 chars): ${pass:0:8}..."
        fi
      done || true

    # Check for FILE privilege
    info "Checking FILE privilege (allows reading/writing OS files via MySQL):"
    FILE_USERS=$(mysql -u root -e \
      "SELECT user, host FROM mysql.user WHERE File_priv='Y';" 2>/dev/null | tail -n +2 || true)
    if [[ -n "$FILE_USERS" ]]; then
      vuln "Users with FILE privilege (can read/write OS files as mysql user):"
      echo "$FILE_USERS" | while IFS=$'\t' read -r usr host; do
        detail "'${usr}'@'${host}' — remove with: REVOKE FILE ON *.* FROM '${usr}'@'${host}';"
      done
      inc_issues
    else
      ok "No users have FILE privilege"
    fi

    # Check for anonymous users
    info "Checking for anonymous MySQL users:"
    ANON_USERS=$(mysql -u root -e \
      "SELECT host FROM mysql.user WHERE user='';" 2>/dev/null | tail -n +2 || true)
    if [[ -n "$ANON_USERS" ]]; then
      vuln "Anonymous MySQL users exist (no username required to connect):"
      echo "$ANON_USERS" | while read -r h; do detail "Anonymous@'$h'"; done
      detail "Fix: DELETE FROM mysql.user WHERE user=''; FLUSH PRIVILEGES;"
      inc_issues
    else
      ok "No anonymous MySQL users"
    fi

    # Check for accounts with old password algorithm
    info "Checking for old-style password hashes (length <= 16 chars):"
    OLD_HASH=$(mysql -u root -e \
      "SELECT user, host FROM mysql.user WHERE LENGTH(password) > 0 AND LENGTH(password) <= 16;" \
      2>/dev/null | tail -n +2 || true)
    if [[ -n "$OLD_HASH" ]]; then
      vuln "Accounts using old (weak) password algorithm:"
      echo "$OLD_HASH" | while IFS=$'\t' read -r u h; do
        detail "'${u}'@'${h}' — fix: SET PASSWORD FOR '${u}'@'${h}' = NEW_PASSWORD('...');"
      done
      inc_issues
    else
      ok "All password hashes use the new (stronger) algorithm"
    fi

    # Check GRANT ALL / super privileges
    info "Checking for overly-privileged users (Super_priv, Grant_priv):"
    SUPER_USERS=$(mysql -u root -e \
      "SELECT user, host FROM mysql.user WHERE Super_priv='Y' AND user != 'root';" \
      2>/dev/null | tail -n +2 || true)
    if [[ -n "$SUPER_USERS" ]]; then
      vuln "Non-root users with SUPER privilege:"
      echo "$SUPER_USERS" | while IFS=$'\t' read -r u h; do detail "'${u}'@'${h}'"; done
      inc_issues
    else
      ok "No non-root users have SUPER privilege"
    fi

  else
    info "MySQL root requires a password (or MySQL is not running)"
    # Still check MYD hash extraction hint
    if [[ -f /var/lib/mysql/mysql/user.MYD ]]; then
      warn "Password hashes may be extractable if you have root OS access:"
      detail "strings /var/lib/mysql/mysql/user.MYD"
    fi
  fi

  # Check for test database
  if $MYSQL_ROOT_NOPASS; then
    info "Checking for 'test' database (accessible by anyone by default):"
    TEST_DB=$(mysql -u root -e "SHOW DATABASES LIKE 'test';" 2>/dev/null | grep -i "test" || true)
    if [[ -n "$TEST_DB" ]]; then
      warn "'test' database exists — anonymous users may have access by default"
      detail "Fix: DROP DATABASE test; DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';"
    else
      ok "No 'test' database found"
    fi
  fi
else
  info "mysql client not found — skipping MySQL deep-dive"
fi

# ── 13. APACHE CONFIGURATION ──────────────────────────────────────────────────
section "13. APACHE CONFIGURATION"

APACHE_CFG=""
for p in /etc/apache2/apache2.conf /etc/httpd/conf/httpd.conf /etc/httpd/httpd.conf; do
  [[ -f "$p" ]] && APACHE_CFG="$p" && break
done

if [[ -z "$APACHE_CFG" ]]; then
  info "Apache config not found — Apache may not be installed"
else
  info "Apache config: $APACHE_CFG"

  # Running user
  APACHE_USER=$(grep -E "^\s*(User|APACHE_RUN_USER)" "$APACHE_CFG" /etc/apache2/envvars 2>/dev/null \
    | grep -v "^#" | head -1 | awk '{print $2}' | tr -d '"' || true)
  APACHE_GROUP=$(grep -E "^\s*(Group|APACHE_RUN_GROUP)" "$APACHE_CFG" /etc/apache2/envvars 2>/dev/null \
    | grep -v "^#" | head -1 | awk '{print $2}' | tr -d '"' || true)

  if [[ "${APACHE_USER}" == "root" ]]; then
    vuln "Apache is running as root — critical privilege escalation risk!"
    inc_issues
  elif [[ -n "$APACHE_USER" ]]; then
    ok "Apache running as user: ${APACHE_USER} / group: ${APACHE_GROUP:-N/A}"
  else
    info "Could not determine Apache run user"
  fi

  # ServerTokens
  SEC_CFG=""
  for p in /etc/apache2/conf.d/security /etc/apache2/conf-enabled/security.conf \
           /etc/apache2/conf-available/security.conf /etc/httpd/conf.d/security.conf; do
    [[ -f "$p" ]] && SEC_CFG="$p" && break
  done

  if [[ -n "$SEC_CFG" ]]; then
    info "Apache security config: $SEC_CFG"

    SERVER_TOKENS=$(grep -i "^\s*ServerTokens" "$SEC_CFG" 2>/dev/null | awk '{print $2}' | tail -1 || true)
    if [[ -z "$SERVER_TOKENS" ]]; then
      warn "ServerTokens not set in $SEC_CFG — defaults to 'Full' (leaks OS/version info)"
      detail "Fix: ServerTokens Prod"
    elif [[ "${SERVER_TOKENS,,}" != "prod" ]]; then
      warn "ServerTokens = $SERVER_TOKENS — leaks server version info"
      detail "Fix: ServerTokens Prod  (in $SEC_CFG)"
    else
      ok "ServerTokens = Prod (minimal version disclosure)"
    fi

    SERVER_SIG=$(grep -i "^\s*ServerSignature" "$SEC_CFG" 2>/dev/null | awk '{print $2}' | tail -1 || true)
    if [[ -z "$SERVER_SIG" ]]; then
      warn "ServerSignature not set — defaults to 'On' (appends server info to error pages)"
      detail "Fix: ServerSignature Off  (in $SEC_CFG)"
    elif [[ "${SERVER_SIG,,}" != "off" ]]; then
      warn "ServerSignature = $SERVER_SIG — version info shown on error pages"
      detail "Fix: ServerSignature Off  (in $SEC_CFG)"
    else
      ok "ServerSignature = Off"
    fi
  else
    warn "Apache security config file not found — ServerTokens/ServerSignature unchecked"
    detail "Checked: /etc/apache2/conf.d/security, conf-enabled/security.conf, etc."
  fi

  # Directory listing (Indexes)
  info "Checking for directory listing (Options Indexes):"
  SITES_DIR=""
  for p in /etc/apache2/sites-enabled /etc/httpd/conf.d; do
    [[ -d "$p" ]] && SITES_DIR="$p" && break
  done
  INDEXES_FILES=()
  # Check main config and sites
  for f in "$APACHE_CFG" ${SITES_DIR:+$SITES_DIR/*}; do
    [[ -f "$f" ]] || continue
    if grep -iqE "Options\s+.*Indexes" "$f" 2>/dev/null; then
      INDEXES_FILES+=("$f")
    fi
  done
  if [[ ${#INDEXES_FILES[@]} -gt 0 ]]; then
    vuln "Directory listing (Options Indexes) is ENABLED in:"
    for f in "${INDEXES_FILES[@]}"; do
      detail "$f"
      grep -nE "Options\s+.*Indexes" "$f" 2>/dev/null | while read -r line; do detail "  Line $line"; done
    done
    detail "Fix: replace 'Indexes' with '-Indexes' in the Options directive"
    inc_issues
  else
    ok "Directory listing (Indexes) does not appear to be enabled"
  fi

  # DocumentRoot permissions
  DOC_ROOT=$(grep -i "^\s*DocumentRoot" "$APACHE_CFG" ${SITES_DIR:+$SITES_DIR/*} 2>/dev/null \
    | grep -v "^#" | head -1 | awk '{print $2}' | tr -d '"' || true)
  if [[ -n "$DOC_ROOT" && -d "$DOC_ROOT" ]]; then
    info "DocumentRoot: $DOC_ROOT"
    DR_PERMS=$(stat -c "%a %U %G" "$DOC_ROOT" 2>/dev/null || true)
    info "Permissions: $DR_PERMS"
    DR_MODE=$(stat -c "%a" "$DOC_ROOT" 2>/dev/null || true)
    if [[ -n "$DR_MODE" ]]; then
      # World-writable docroot?
      if (( (8#$DR_MODE & 8#002) != 0 )); then
        vuln "DocumentRoot $DOC_ROOT is world-writable!"
        detail "Fix: chmod o-w $DOC_ROOT"
        inc_issues
      fi
      # Owned by apache/www-data user is fine; owned by root is also fine
      DR_OWNER=$(stat -c "%U" "$DOC_ROOT" 2>/dev/null || true)
      if [[ "$DR_OWNER" == "${APACHE_USER}" ]]; then
        warn "DocumentRoot owned by Apache run user ($APACHE_USER) — web server can modify files"
        detail "Consider ownership by a separate deploy user to prevent web shell writes"
      else
        ok "DocumentRoot not owned by Apache run user ($DR_OWNER) — good"
      fi
    fi
  fi

  # .htaccess override
  info "Checking if .htaccess overrides are enabled (AllowOverride):"
  if grep -qiE "^\s*AllowOverride\s+All" "$APACHE_CFG" ${SITES_DIR:+$SITES_DIR/*} 2>/dev/null; then
    warn "AllowOverride All found — users can override security settings via .htaccess"
    detail "Consider 'AllowOverride None' or a minimal set unless specifically needed"
  else
    ok "AllowOverride All not found (or restricted)"
  fi

  # mod_status / mod_info exposure
  for mod in server-status server-info; do
    if [[ -f /etc/apache2/mods-enabled/${mod}.conf ]] || \
       grep -rqiE "SetHandler\s+${mod}" /etc/apache2/ 2>/dev/null; then
      warn "Apache mod ${mod} appears to be enabled — may expose internal server info"
      detail "Restrict with 'Require ip 127.0.0.1' or disable if not needed"
    fi
  done
fi

# ── 14. PHP CONFIGURATION ─────────────────────────────────────────────────────
section "14. PHP CONFIGURATION"

# Locate PHP config directory used by Apache
PHP_INI=""
PHP_CONF_DIR=""
for p in \
  /etc/php5/apache2/php.ini \
  /etc/php/7.0/apache2/php.ini \
  /etc/php/7.2/apache2/php.ini \
  /etc/php/7.4/apache2/php.ini \
  /etc/php/8.0/apache2/php.ini \
  /etc/php/8.1/apache2/php.ini \
  /etc/php/8.2/apache2/php.ini \
  /etc/php/8.3/apache2/php.ini; do
  if [[ -f "$p" ]]; then
    PHP_INI="$p"
    PHP_CONF_DIR="$(dirname "$p")"
    break
  fi
done

# Also try php --ini if available
if [[ -z "$PHP_INI" ]] && command -v php &>/dev/null; then
  PHP_INI=$(php --ini 2>/dev/null | grep "Loaded Configuration" | awk -F': ' '{print $2}' | tr -d ' ' || true)
  PHP_CONF_DIR=$(dirname "$PHP_INI" 2>/dev/null || true)
fi

# Detect PHP module version from Apache mods
PHP_MOD_VER=""
for f in /etc/apache2/mods-enabled/php*.load; do
  [[ -f "$f" ]] || continue
  PHP_MOD_VER=$(basename "$f" .load)
  break
done

if [[ -z "$PHP_INI" ]]; then
  info "PHP ini file not found — PHP may not be installed or uses a different path"
  [[ -n "$PHP_MOD_VER" ]] && info "Apache PHP module detected: $PHP_MOD_VER"
else
  info "PHP ini: $PHP_INI"
  [[ -n "$PHP_MOD_VER" ]] && info "Apache PHP module: $PHP_MOD_VER"

  # Helper: get a php.ini value (handles comments, case-insensitive, last match wins)
  php_get() {
    grep -iE "^\s*${1}\s*=" "$PHP_INI" 2>/dev/null \
      | grep -v "^\s*;" \
      | tail -1 \
      | awk -F= '{gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2}' \
      | tr -d '"' \
      || true
  }

  # ── expose_php ──
  VAL=$(php_get "expose_php")
  if [[ -z "$VAL" || "${VAL,,}" == "on" || "$VAL" == "1" ]]; then
    vuln "expose_php = ${VAL:-On (default)} — PHP version sent in X-Powered-By HTTP header"
    detail "Fix: expose_php = Off  in $PHP_INI"
    inc_issues
  else
    ok "expose_php = Off (version not leaked in HTTP headers)"
  fi

  # ── display_errors ──
  VAL=$(php_get "display_errors")
  if [[ -z "$VAL" || "${VAL,,}" == "on" || "$VAL" == "1" ]]; then
    vuln "display_errors = ${VAL:-On (default)} — errors shown to users, leaks code paths/info"
    detail "Fix: display_errors = Off  in $PHP_INI"
    inc_issues
  else
    ok "display_errors = Off"
  fi

  # ── error_reporting ──
  VAL=$(php_get "error_reporting")
  if [[ -z "$VAL" ]]; then
    warn "error_reporting not explicitly set — errors may be silently ignored"
    detail "Fix: error_reporting = E_ALL  in $PHP_INI"
  elif echo "$VAL" | grep -q "E_ALL"; then
    ok "error_reporting includes E_ALL ($VAL)"
  else
    warn "error_reporting = $VAL — consider E_ALL for full logging"
    detail "Fix: error_reporting = E_ALL  in $PHP_INI"
  fi

  # ── log_errors ──
  VAL=$(php_get "log_errors")
  if [[ -z "$VAL" || "${VAL,,}" == "off" || "$VAL" == "0" ]]; then
    vuln "log_errors = ${VAL:-Off (default)} — PHP errors NOT being logged!"
    detail "Fix: log_errors = On  in $PHP_INI"
    inc_issues
  else
    ok "log_errors = On"
  fi

  # ── safe_mode (PHP < 5.4) ──
  VAL=$(php_get "safe_mode")
  if [[ -n "$VAL" ]]; then   # only present in older PHP
    if [[ "${VAL,,}" == "off" || "$VAL" == "0" ]]; then
      warn "safe_mode = Off — safe_mode is disabled (adds minor attacker friction when On)"
      detail "Fix: safe_mode = On  in $PHP_INI  (PHP < 5.4 only; removed in PHP 5.4+)"
    else
      ok "safe_mode = On"
    fi
  fi

  # ── disable_functions ──
  VAL=$(php_get "disable_functions")
  DANGEROUS_FUNCS=(eval exec passthru shell_exec system proc_open popen
                   pcntl_exec assert base64_decode phpinfo)
  if [[ -z "$VAL" ]]; then
    vuln "disable_functions is empty — ALL PHP functions are available to scripts!"
    detail "Fix: disable_functions = exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec"
    inc_issues
  else
    info "disable_functions = $VAL"
    MISSING_BLOCKS=()
    for fn in "${DANGEROUS_FUNCS[@]}"; do
      if ! echo "$VAL" | grep -qi "$fn"; then
        MISSING_BLOCKS+=("$fn")
      fi
    done
    if [[ ${#MISSING_BLOCKS[@]} -gt 0 ]]; then
      warn "Dangerous functions NOT in disable_functions:"
      for fn in "${MISSING_BLOCKS[@]}"; do detail "$fn"; done
      detail "Consider adding them to disable_functions in $PHP_INI"
    else
      ok "All commonly dangerous functions appear to be disabled"
    fi
  fi

  # ── allow_url_include ──
  VAL=$(php_get "allow_url_include")
  if [[ "${VAL,,}" == "on" || "$VAL" == "1" ]]; then
    vuln "allow_url_include = On — remote file inclusion (RFI) attacks possible!"
    detail "Fix: allow_url_include = Off  in $PHP_INI"
    inc_issues
  else
    ok "allow_url_include = ${VAL:-Off (default)}"
  fi

  # ── allow_url_fopen ──
  VAL=$(php_get "allow_url_fopen")
  if [[ -z "$VAL" || "${VAL,,}" == "on" || "$VAL" == "1" ]]; then
    warn "allow_url_fopen = ${VAL:-On (default)} — scripts can open remote URLs via fopen/file_get_contents"
    detail "Disable unless explicitly needed: allow_url_fopen = Off  in $PHP_INI"
  else
    ok "allow_url_fopen = Off"
  fi

  # ── register_globals (PHP < 5.4) ──
  VAL=$(php_get "register_globals")
  if [[ -n "$VAL" && ("${VAL,,}" == "on" || "$VAL" == "1") ]]; then
    vuln "register_globals = On — GET/POST vars injected as globals, severe security risk!"
    detail "Fix: register_globals = Off  in $PHP_INI"
    inc_issues
  fi

  # ── magic_quotes_gpc (PHP < 5.4) ──
  VAL=$(php_get "magic_quotes_gpc")
  if [[ -n "$VAL" && ("${VAL,,}" == "on" || "$VAL" == "1") ]]; then
    warn "magic_quotes_gpc = On — deprecated, may give false sense of SQL injection protection"
    detail "Fix: magic_quotes_gpc = Off  in $PHP_INI and use prepared statements"
  fi

  # ── session settings ──
  info "Session security settings:"
  VAL=$(php_get "session.cookie_httponly")
  if [[ -z "$VAL" || "${VAL,,}" == "off" || "$VAL" == "0" ]]; then
    warn "session.cookie_httponly = ${VAL:-Off} — session cookies accessible to JavaScript (XSS risk)"
    detail "Fix: session.cookie_httponly = On  in $PHP_INI"
  else
    ok "session.cookie_httponly = On"
  fi

  VAL=$(php_get "session.cookie_secure")
  if [[ -z "$VAL" || "${VAL,,}" == "off" || "$VAL" == "0" ]]; then
    warn "session.cookie_secure = ${VAL:-Off} — session cookies sent over HTTP (not HTTPS-only)"
    detail "Fix: session.cookie_secure = On  if the site uses HTTPS"
  else
    ok "session.cookie_secure = On"
  fi

  VAL=$(php_get "session.use_strict_mode")
  if [[ -z "$VAL" || "${VAL,,}" == "off" || "$VAL" == "0" ]]; then
    warn "session.use_strict_mode = ${VAL:-Off} — uninitialized session IDs accepted (session fixation risk)"
    detail "Fix: session.use_strict_mode = On  in $PHP_INI"
  else
    ok "session.use_strict_mode = On"
  fi

  # ── Suhosin extension ──
  section "14a. SUHOSIN EXTENSION (PHP hardening)"
  SUHOSIN_INI=""
  for p in \
    "$PHP_CONF_DIR/conf.d/suhosin.ini" \
    /etc/php5/conf.d/suhosin.ini \
    /etc/php5/apache2/conf.d/suhosin.ini; do
    [[ -f "$p" ]] && SUHOSIN_INI="$p" && break
  done

  if [[ -z "$SUHOSIN_INI" ]]; then
    warn "Suhosin extension not found — additional PHP hardening layer is missing"
    detail "Install: apt-get install php5-suhosin  (or equivalent for your PHP version)"
    detail "Suhosin adds memory protection, logging, and execution guards"
  else
    info "Suhosin config: $SUHOSIN_INI"

    # Helper for suhosin ini
    suhosin_get() {
      grep -iE "^\s*${1}\s*=" "$SUHOSIN_INI" 2>/dev/null \
        | grep -v "^\s*;" | tail -1 \
        | awk -F= '{gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2}' | tr -d '"' || true
    }

    # suhosin.log.syslog
    VAL=$(suhosin_get "suhosin.log.syslog")
    if [[ -z "$VAL" || "$VAL" == "0" ]]; then
      warn "suhosin.log.syslog not set to S_ALL — Suhosin events not logged to syslog"
      detail "Fix: suhosin.log.syslog = S_ALL  in $SUHOSIN_INI"
    else
      ok "suhosin.log.syslog = $VAL"
    fi

    # suhosin.executor.include.max_traversal
    VAL=$(suhosin_get "suhosin.executor.include.max_traversal")
    if [[ -z "$VAL" ]]; then
      warn "suhosin.executor.include.max_traversal not set — directory traversal attacks unrestricted"
      detail "Fix: suhosin.executor.include.max_traversal = 3  in $SUHOSIN_INI"
    elif [[ "$VAL" -le 0 ]]; then
      warn "suhosin.executor.include.max_traversal = $VAL — traversal not restricted"
      detail "Fix: set to 3 to limit traversal depth while keeping apps functional"
    else
      ok "suhosin.executor.include.max_traversal = $VAL"
    fi

    # suhosin.executor.disable_eval
    VAL=$(suhosin_get "suhosin.executor.disable_eval")
    if [[ -z "$VAL" || "${VAL,,}" == "off" || "$VAL" == "0" ]]; then
      warn "suhosin.executor.disable_eval = ${VAL:-Off} — eval() is still executable"
      detail "Fix: suhosin.executor.disable_eval = On  in $SUHOSIN_INI"
    else
      ok "suhosin.executor.disable_eval = On (eval() blocked)"
    fi

    # suhosin.executor.disable_emodifier
    VAL=$(suhosin_get "suhosin.executor.disable_emodifier")
    if [[ -z "$VAL" || "${VAL,,}" == "off" || "$VAL" == "0" ]]; then
      warn "suhosin.executor.disable_emodifier = ${VAL:-Off} — preg_replace /e modifier usable for code exec"
      detail "Fix: suhosin.executor.disable_emodifier = On  in $SUHOSIN_INI"
    else
      ok "suhosin.executor.disable_emodifier = On (preg_replace /e blocked)"
    fi
  fi
fi

# ── 15. PHP IN USER PUBLIC DIRECTORIES ───────────────────────────────────────
section "15. PHP IN USER PUBLIC DIRECTORIES"
# The document flags that PHP should be disabled for /home/*/public_html.
# If users can run PHP in their public_html, they can pivot from their UID
# to that of the web server (e.g. www-data).
PHP_MOD_CONF=""
for p in /etc/apache2/mods-enabled/php*.conf; do
  [[ -f "$p" ]] && PHP_MOD_CONF="$p" && break
done

if [[ -z "$PHP_MOD_CONF" ]]; then
  info "No PHP Apache module config found — PHP may not be installed"
else
  info "PHP module config: $PHP_MOD_CONF"
  if grep -q "mod_userdir" "$PHP_MOD_CONF" 2>/dev/null; then
    if grep -qE "php_admin_value\s+engine\s+[Oo]ff" "$PHP_MOD_CONF" 2>/dev/null; then
      ok "PHP is disabled in user public_html directories (php_admin_value engine Off)"
    else
      vuln "PHP is NOT disabled in user public_html directories!"
      detail "Users can run PHP as the web server user from ~/public_html/"
      detail "Fix: add inside <IfModule mod_userdir.c> block in $PHP_MOD_CONF:"
      detail "  <Directory /home/*/public_html>"
      detail "    php_admin_value engine Off"
      detail "  </Directory>"
      inc_issues
    fi
  else
    warn "mod_userdir block not found in $PHP_MOD_CONF"
    detail "Cannot confirm PHP is disabled for user public directories"
    detail "Manually verify or add the mod_userdir restriction"
  fi
fi

# ── 16. APACHE SSL CONFIGURATION ──────────────────────────────────────────────
section "16. APACHE SSL CONFIGURATION"
# Check if SSL module is enabled
SSL_ENABLED=false
if [[ -f /etc/apache2/mods-enabled/ssl.load ]] || \
   [[ -f /etc/apache2/mods-enabled/ssl.conf ]]; then
  SSL_ENABLED=true
fi

if ! $SSL_ENABLED; then
  info "Apache SSL module (mod_ssl) does not appear to be enabled"
  detail "If this server serves HTTPS, enable mod_ssl: a2enmod ssl"
  detail "If it runs HTTP-only behind a load balancer, this may be intentional"
else
  info "Apache SSL module is enabled — checking configuration..."

  # Find SSL virtual host configs
  SSL_CFGS=()
  for p in /etc/apache2/sites-enabled/*.conf /etc/apache2/sites-enabled/*; do
    [[ -f "$p" ]] || continue
    grep -qiE "SSLEngine|ssl:" "$p" 2>/dev/null && SSL_CFGS+=("$p")
  done
  [[ ${#SSL_CFGS[@]} -eq 0 ]] && SSL_CFGS=("/etc/apache2/mods-enabled/ssl.conf")

  for SSL_CFG in "${SSL_CFGS[@]}"; do
    [[ -f "$SSL_CFG" ]] || continue
    info "SSL config: $SSL_CFG"

    # SSLv2 / SSLv3 disabled?
    SSL_PROTO=$(grep -iE "^\s*SSLProtocol" "$SSL_CFG" 2>/dev/null | tail -1 || true)
    if [[ -z "$SSL_PROTO" ]]; then
      warn "SSLProtocol not explicitly set — SSLv2/SSLv3 may be enabled"
      detail "Fix: SSLProtocol All -SSLv2 -SSLv3  in $SSL_CFG"
    elif echo "$SSL_PROTO" | grep -qi "SSLv2\b" && ! echo "$SSL_PROTO" | grep -qi "\-SSLv2"; then
      vuln "SSLv2 is enabled — cryptographically broken!"
      detail "Fix: SSLProtocol All -SSLv2 -SSLv3  in $SSL_CFG"
      inc_issues
    elif echo "$SSL_PROTO" | grep -qi "SSLv3\b" && ! echo "$SSL_PROTO" | grep -qi "\-SSLv3"; then
      vuln "SSLv3 is enabled — vulnerable to POODLE attack!"
      detail "Fix: SSLProtocol All -SSLv2 -SSLv3  in $SSL_CFG"
      inc_issues
    else
      ok "SSLProtocol: $SSL_PROTO"
    fi

    # Weak ciphers
    SSL_CIPHER=$(grep -iE "^\s*SSLCipherSuite" "$SSL_CFG" 2>/dev/null | tail -1 || true)
    if [[ -z "$SSL_CIPHER" ]]; then
      warn "SSLCipherSuite not explicitly set — default may include weak ciphers"
      detail "Fix: SSLCipherSuite HIGH:!aNULL:!MD5:!SSLv2:!RC4  in $SSL_CFG"
    else
      info "SSLCipherSuite: $SSL_CIPHER"
      # Flag known weak cipher keywords
      for weak in RC4 DES MD5 NULL EXPORT ADH aNULL eNULL LOW; do
        if echo "$SSL_CIPHER" | grep -qi "\b${weak}\b" && \
           ! echo "$SSL_CIPHER" | grep -qi "!\s*${weak}"; then
          warn "Weak cipher component found in SSLCipherSuite: ${weak}"
          detail "Prefix with !${weak} in SSLCipherSuite to exclude it"
        fi
      done
    fi

    # SSL private key file permissions
    info "Checking SSL private key file permissions:"
    grep -iE "^\s*SSLCertificateKeyFile" "$SSL_CFG" 2>/dev/null | while read -r kline; do
      KEYFILE=$(echo "$kline" | awk '{print $2}' | tr -d '"')
      [[ -z "$KEYFILE" || ! -f "$KEYFILE" ]] && continue
      KEY_PERMS=$(stat -c "%a" "$KEYFILE" 2>/dev/null || true)
      KEY_OWNER=$(stat -c "%U" "$KEYFILE" 2>/dev/null || true)
      if [[ -n "$KEY_PERMS" ]]; then
        # Should not be readable by group or others
        if (( (8#$KEY_PERMS & 8#077) != 0 )); then
          vuln "SSL private key is readable by group/others: $KEYFILE  (perms: $KEY_PERMS)"
          detail "Fix: chmod 600 \"$KEYFILE\""
          inc_issues
        else
          ok "SSL private key permissions OK: $KEYFILE  ($KEY_PERMS / $KEY_OWNER)"
        fi
      fi
    done || true

    # SSLHonorCipherOrder
    HONOR=$(grep -iE "^\s*SSLHonorCipherOrder" "$SSL_CFG" 2>/dev/null | awk '{print $2}' | tail -1 || true)
    if [[ -z "$HONOR" || "${HONOR,,}" != "on" ]]; then
      warn "SSLHonorCipherOrder = ${HONOR:-Off (default)} — server does not enforce cipher preference"
      detail "Fix: SSLHonorCipherOrder On  in $SSL_CFG"
    else
      ok "SSLHonorCipherOrder = On"
    fi
  done
fi

# ── SUMMARY ───────────────────────────────────────────────────────────────────
echo -e "\n${BCYAN}══════════════════════════════════════════${RESET}"
echo -e "${BCYAN}  AUDIT SUMMARY${RESET}"
echo -e "${BCYAN}══════════════════════════════════════════${RESET}"
if [[ $ISSUES -eq 0 ]]; then
  echo -e "\n  ${BGREEN}No critical vulnerabilities found. Keep hardening!${RESET}\n"
else
  echo -e "\n  ${BRED}${BOLD}$ISSUES critical issue(s) found — review items marked [✘ VULN] above.${RESET}"
  echo -e "  ${BYELLOW}Items marked [⚠ WARN] are recommended improvements.${RESET}\n"
fi
echo -e "  ${BOLD}Suggested next steps:${RESET}"
echo -e "  ${BLUE}•${RESET} Restart SSH after changes:   ${CYAN}systemctl restart sshd${RESET}"
echo -e "  ${BLUE}•${RESET} Restart MySQL after changes: ${CYAN}systemctl restart mysql${RESET}"
echo -e "  ${BLUE}•${RESET} Check GTFOBins for SUID abuse: ${CYAN}https://gtfobins.github.io${RESET}"
echo -e "  ${BLUE}•${RESET} Run full LinPEAS for deeper audit: ${CYAN}https://github.com/carlospolop/PEASS-ng${RESET}\n"