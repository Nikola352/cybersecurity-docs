#!/bin/bash
# security_review.sh - Combined Linux Security Review Script
# Sections: system → network → filesystem → users → services
# Inspired by Lynis / LinPEAS / hardening audits
# Requires root for complete results

# ============================================================
# Color definitions
# ============================================================
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# Extra colors used by services section
BRED='\033[1;31m'
BGREEN='\033[1;32m'
BYELLOW='\033[1;33m'
BCYAN='\033[1;36m'
CYAN='\033[0;36m'
ORANGE='\033[38;5;208m'
RESET="$NC"

print_section()   { echo -e "\n${BOLD}${BLUE}════════════════════════════════════════${NC}"; \
                    echo -e "${BOLD}${BLUE}  $1${NC}"; \
                    echo -e "${BOLD}${BLUE}════════════════════════════════════════${NC}"; }
print_subsection(){ echo -e "\n${BOLD}--- $1 ---${NC}"; }
print_ok()        { echo -e "  ${GREEN}[OK]${NC}   $1"; }
print_warning()   { echo -e "  ${YELLOW}[WARN]${NC} $1"; }
print_bad()       { echo -e "  ${RED}[BAD]${NC}  $1"; }
print_info()      { echo -e "  ${BOLD}[*]${NC}   $1"; }

# Compatibility aliases for services-section style calls
section() { print_section "$@"; }
ok()      { print_ok "$@"; }
warn()    { print_warning "$@"; }
vuln()    { print_bad "$@"; }
info()    { print_info "$@"; }
detail()  { echo -e "        ${BLUE}⤷${NC} $1"; }

# ============================================================
# Root check
# ============================================================
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}[!] This script must be run as root. Re-run with sudo.${NC}" >&2
        exit 1
    fi
}

# ============================================================
# SYSTEM REVIEW FUNCTIONS
# ============================================================

# NVD CVE API helper
# ============================================================

# query_nvd_cves <cpe_string> <human_label>
# Queries the NIST NVD API v2.0, parses JSON with python3, prints top-5 by CVSS.
# Warns loudly on network failure so the reviewer knows to check manually.
query_nvd_cves() {
    local cpe="$1" label="$2"
    local url="https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=${cpe}&resultsPerPage=50"
    local response

    print_info "Querying NVD for: $label"
    response=$(curl -sf --max-time 15 --connect-timeout 5 "$url" 2>/dev/null)
    if [ $? -ne 0 ] || [ -z "$response" ]; then
        print_bad  "!!! CVE lookup FAILED for $label — no internet or NVD API unreachable !!!"
        print_bad  "!!! Manually review CVEs at: https://nvd.nist.gov/vuln/search          !!!"
        return
    fi

    echo "$response" | python3 -c "
import sys, json

def cpe_matches_product(cve, product_substr):
    '''Return True only if the CVE has a CPE where product_substr is the actual target product,
    not just a platform/OS dependency of other software.'''
    for cfg in cve.get('configurations', []):
        for node in cfg.get('nodes', []):
            for match in node.get('cpeMatch', []):
                if product_substr in match.get('criteria', ''):
                    return True
    return False

data = json.load(sys.stdin)
all_vulns = data.get('vulnerabilities', [])
total_raw = data.get('totalResults', 0)

# Filter: only keep CVEs where the queried product is the actual affected component,
# not a platform dependency (e.g. Adobe Flash 'on Linux' gets filtered out here).
product_key = sys.argv[1] if len(sys.argv) > 1 else ''
if product_key:
    vulns = [v for v in all_vulns if cpe_matches_product(v['cve'], product_key)]
else:
    vulns = all_vulns

total = len(vulns)
print(f'  Total CVEs found (product-filtered): {total}  (raw NVD matches: {total_raw})')
if total == 0:
    print('  (No CVEs matched this exact CPE version string.')
    print('   NVD uses version ranges in many advisories — verify manually.)')
    sys.exit(0)
scored = []
for v in vulns:
    cve = v['cve']
    m = cve.get('metrics', {})
    score = 0.0
    sev = 'N/A'
    for key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
        if key in m:
            entry = m[key][0]['cvssData']
            score = float(entry.get('baseScore', 0))
            sev = entry.get('baseSeverity', m[key][0].get('baseSeverity', 'N/A'))
            break
    desc = next((d['value'] for d in cve.get('descriptions', []) if d['lang'] == 'en'), 'N/A')
    scored.append((score, cve['id'], sev, desc[:120]))
scored.sort(reverse=True)
print(f'  Top {min(5, len(scored))} by CVSS score:')
for score, cid, sev, desc in scored[:5]:
    print(f'    [{score:4.1f} {sev:8s}] {cid}: {desc}')
if total > 5:
    print(f'  ... and {total - 5} more. Full list: https://nvd.nist.gov/vuln/search')
" "$2"
}

# ============================================================
# SECTION 1: Operating System
# ============================================================

check_os() {
    print_section "1. Operating System"

    local DISTRO_ID="" DISTRO_VERSION="" DISTRO_PRETTY=""

    if [ -f /etc/os-release ]; then
        DISTRO_ID=$(grep -oP '(?<=^ID=).*' /etc/os-release | tr -d '"' | tr '[:upper:]' '[:lower:]')
        DISTRO_VERSION=$(grep -oP '(?<=^VERSION_ID=).*' /etc/os-release | tr -d '"')
        DISTRO_PRETTY=$(grep -oP '(?<=^PRETTY_NAME=).*' /etc/os-release | tr -d '"')
        print_info "Distribution: $DISTRO_PRETTY"
        print_info "ID: $DISTRO_ID  |  Version: $DISTRO_VERSION  |  Arch: $(uname -m)"
    elif command -v lsb_release &>/dev/null; then
        DISTRO_PRETTY=$(lsb_release -d 2>/dev/null | awk -F: '{print $2}' | xargs)
        DISTRO_ID=$(lsb_release -i 2>/dev/null | awk -F: '{print $2}' | xargs | tr '[:upper:]' '[:lower:]')
        DISTRO_VERSION=$(lsb_release -r 2>/dev/null | awk -F: '{print $2}' | xargs)
        print_info "Distribution: $DISTRO_PRETTY"
        print_info "ID: $DISTRO_ID  |  Version: $DISTRO_VERSION  |  Arch: $(uname -m)"
    elif [ -f /etc/debian_version ]; then
        DISTRO_ID="debian"
        DISTRO_VERSION=$(cat /etc/debian_version)
        print_info "Debian version: $DISTRO_VERSION"
    elif [ -f /etc/redhat-release ]; then
        print_info "$(cat /etc/redhat-release)"
    else
        print_warning "Could not determine OS distribution"
    fi

    echo ""

    # EOL table — "distro_id:version:YYYY-MM-DD"
    local EOL_TABLE=(
        "ubuntu:16.04:2021-04-30"
        "ubuntu:18.04:2023-04-30"
        "ubuntu:20.04:2025-04-30"
        "ubuntu:22.04:2027-04-30"
        "ubuntu:24.04:2029-04-30"
        "debian:8:2020-06-30"
        "debian:9:2022-06-30"
        "debian:10:2024-06-30"
        "debian:11:2026-08-31"
        "debian:12:2028-06-30"
        "centos:6:2020-11-30"
        "centos:7:2024-06-30"
        "centos:8:2021-12-31"
        "rhel:7:2024-06-30"
        "rhel:8:2029-05-31"
        "rhel:9:2032-05-31"
        "linuxmint:20:2025-04-30"
        "linuxmint:21:2027-04-30"
        "pop:22.04:2027-04-30"
        "pop:24.04:2029-04-30"
    )

    local today
    today=$(date +%Y-%m-%d)
    local eol_found=0

    if [ -n "$DISTRO_ID" ] && [ -n "$DISTRO_VERSION" ]; then
        for entry in "${EOL_TABLE[@]}"; do
            local tbl_id="${entry%%:*}"
            local rest="${entry#*:}"
            local tbl_ver="${rest%%:*}"
            local tbl_eol="${rest##*:}"
            if [ "$tbl_id" = "$DISTRO_ID" ] && [ "$tbl_ver" = "$DISTRO_VERSION" ]; then
                eol_found=1
                if [[ "$today" > "$tbl_eol" ]]; then
                    print_bad "OS reached End of Life on $tbl_eol — no security patches issued since then"
                    print_bad "Every CVE discovered after EOL is permanently unpatched on this system"
                else
                    print_ok "OS is supported until $tbl_eol"
                fi
                break
            fi
        done
        if [ "$eol_found" -eq 0 ]; then
            print_info "EOL date for '$DISTRO_ID $DISTRO_VERSION' not in built-in table — verify manually"
        fi
    fi

    # OS CVE lookup
    print_subsection "OS CVE Check (NVD API)"
    if ! command -v curl &>/dev/null; then
        print_warning "curl not found — skipping OS CVE lookup"
        return
    fi
    if ! command -v python3 &>/dev/null; then
        print_warning "python3 not found — skipping OS CVE lookup"
        return
    fi

    local OS_CPE="" OS_PRODUCT_KEY=""
    local cve_version="$DISTRO_VERSION"
    # Pop!_OS is Ubuntu-based; map to Ubuntu CPE for CVE lookups
    local lookup_id="$DISTRO_ID"
    if [ "$DISTRO_ID" = "pop" ]; then
        lookup_id="ubuntu"
        print_info "Pop!_OS is Ubuntu-based — using Ubuntu CPE for CVE lookup"
    fi

    case "$lookup_id" in
        ubuntu)
            OS_CPE="cpe:2.3:o:canonical:ubuntu_linux:${cve_version}:*:*:*:*:*:*:*"
            OS_PRODUCT_KEY="canonical:ubuntu_linux"
            ;;
        debian)
            OS_CPE="cpe:2.3:o:debian:debian_linux:${cve_version}:*:*:*:*:*:*:*"
            OS_PRODUCT_KEY="debian:debian_linux"
            ;;
        rhel|redhat)
            OS_CPE="cpe:2.3:o:redhat:enterprise_linux:${cve_version}:*:*:*:*:*:*:*"
            OS_PRODUCT_KEY="redhat:enterprise_linux"
            ;;
        centos)
            OS_CPE="cpe:2.3:o:centos:centos:${cve_version}:*:*:*:*:*:*:*"
            OS_PRODUCT_KEY="centos:centos"
            ;;
        *)
            print_info "OS CVE lookup not implemented for distro '$DISTRO_ID' — check NVD manually"
            return
            ;;
    esac

    print_info "Note: CPE matching is exact-version. CVEs with version ranges may not appear here."
    query_nvd_cves "$OS_CPE" "${DISTRO_PRETTY:-$DISTRO_ID $DISTRO_VERSION}" "$OS_PRODUCT_KEY"
}

# ============================================================
# SECTION 2: Kernel
# ============================================================

check_kernel() {
    print_section "2. Kernel Version"

    print_info "Full kernel info (uname -a):"
    uname -a
    echo ""

    # Uptime
    local uptime_out
    uptime_out=$(uptime)
    print_info "Uptime: $uptime_out"
    echo ""

    local uptime_days
    uptime_days=$(uptime 2>/dev/null | grep -oP '\bup\s+\K\d+(?=\s+day)' || true)
    if [ -n "$uptime_days" ] && [ "$uptime_days" -gt 30 ] 2>/dev/null; then
        print_warning "System up $uptime_days days — a kernel update requires a reboot, making this unlikely"
        print_warning "Kernel is likely running with unpatched vulnerabilities from the past $uptime_days days"
    elif [ -n "$uptime_days" ]; then
        print_ok "Uptime is $uptime_days days — recent enough that kernel may have been patched"
    else
        print_info "Uptime < 1 day (system rebooted recently or uptime format not parsed)"
    fi
}

check_kernel_cves() {
    print_section "3. Kernel CVE Check (NVD API)"

    if ! command -v curl &>/dev/null; then
        print_warning "curl not found — skipping kernel CVE lookup"
        return
    fi
    if ! command -v python3 &>/dev/null; then
        print_warning "python3 not found — skipping kernel CVE lookup"
        return
    fi

    local kernel_full kernel_semver
    kernel_full=$(uname -r)
    kernel_semver=$(echo "$kernel_full" | grep -oP '^\d+\.\d+\.\d+')

    if [ -z "$kernel_semver" ]; then
        print_warning "Could not extract semver from kernel string: '$kernel_full'"
        print_warning "Check NVD manually: https://nvd.nist.gov/vuln/search"
        return
    fi

    print_info "Kernel string:  $kernel_full"
    print_info "CPE version:    $kernel_semver"
    print_info "Note: NVD CPE matching is exact-version. CVEs expressed as version ranges"
    print_info "      (e.g., 'affects <= 6.1') may not appear — always verify on NVD."
    echo ""

    local kernel_cpe="cpe:2.3:o:linux:linux_kernel:${kernel_semver}:*:*:*:*:*:*:*"
    query_nvd_cves "$kernel_cpe" "Linux kernel $kernel_semver" "linux:linux_kernel"
}

# ============================================================
# SECTION 3: Time Management
# ============================================================

check_timezone() {
    print_section "4. Timezone"

    local tz=""
    if [ -f /etc/timezone ]; then
        tz=$(cat /etc/timezone)
        print_info "Source: /etc/timezone"
    elif command -v timedatectl &>/dev/null; then
        tz=$(timedatectl 2>/dev/null | grep -oP '(?<=Time zone: )\S+')
        print_info "Source: timedatectl"
    fi

    if [ -n "$tz" ]; then
        print_info "Timezone: $tz"
        echo ""
        if [ "$tz" = "UTC" ] || [ "$tz" = "Etc/UTC" ]; then
            print_ok "UTC timezone — no DST jumps; log timestamps are stable and correlatable"
        else
            print_warning "Timezone is '$tz' (not UTC)"
            print_warning "DST transitions cause clock jumps (±1h) — log entries appear to skip or reverse"
            print_warning "Production servers should run UTC to ensure reliable forensic log correlation"
        fi
    else
        print_warning "Could not determine timezone"
    fi
}

check_ntp() {
    print_section "5. NTP Time Synchronization"

    local ntp_found=0

    # --- ntpd ---
    if ps -edf 2>/dev/null | grep -q '[n]tpd'; then
        ntp_found=1
        print_ok "ntpd is running"
        if command -v ntpq &>/dev/null; then
            print_subsection "NTP peers (ntpq -p -n)"
            ntpq -p -n 2>/dev/null || print_warning "ntpq returned an error"
            echo ""
            local synced
            synced=$(ntpq -p -n 2>/dev/null | grep -c '^\*' || echo "0")
            if [ "$synced" -gt 0 ]; then
                print_ok "Synchronized to $synced peer(s) (line starting with *)"
            else
                print_warning "ntpd running but not synchronized to any peer"
            fi
        else
            print_info "ntpq not found — cannot check peer sync status"
        fi
    fi

    # --- chronyd ---
    if ps -edf 2>/dev/null | grep -q '[c]hronyd'; then
        ntp_found=1
        print_ok "chronyd is running"
        if command -v chronyc &>/dev/null; then
            print_subsection "chrony tracking"
            chronyc tracking 2>/dev/null
            echo ""
            print_subsection "chrony sources"
            chronyc sources 2>/dev/null
            echo ""
            local synced_src
            synced_src=$(chronyc sources 2>/dev/null | grep -c '^\^\*' || echo "0")
            if [ "$synced_src" -gt 0 ]; then
                print_ok "chronyd synchronized (source marked with *)"
            else
                print_warning "chronyd running but no synchronized source found"
            fi
        else
            print_info "chronyc not found — cannot check sync status"
        fi
    fi

    # --- systemd-timesyncd (only if chronyd/ntpd not already detected) ---
    # When chronyd runs, timedatectl also reports NTP service: active — that refers to chronyd,
    # not timesyncd. Check the specific service unit to avoid double-reporting.
    if command -v timedatectl &>/dev/null; then
        local timesyncd_active
        timesyncd_active=$(systemctl is-active systemd-timesyncd 2>/dev/null)
        if [ "$timesyncd_active" = "active" ] && [ "$ntp_found" -eq 0 ]; then
            ntp_found=1
            print_ok "systemd-timesyncd is active"
        fi
        # Always show timedatectl for clock sync status, regardless of which daemon runs
        print_subsection "timedatectl status"
        timedatectl 2>/dev/null
        echo ""
        local clk_synced
        clk_synced=$(timedatectl 2>/dev/null | grep -oP '(?<=System clock synchronized: )\S+')
        if [ "$clk_synced" = "yes" ]; then
            print_ok "System clock is synchronized"
        else
            print_warning "NTP active but system clock not yet synchronized"
        fi
    fi

    echo ""
    if [ "$ntp_found" -eq 0 ]; then
        print_bad "No NTP daemon found (ntpd, chronyd, systemd-timesyncd)"
        print_bad "System clock may drift — log timestamps, SSL certs, and time-based auth will be unreliable"
    fi
}

# ============================================================
# SECTION 4: Installed Packages
# ============================================================

check_packages() {
    print_section "6. Installed Packages"

    local PKG_MGR=""
    if command -v dpkg &>/dev/null; then
        PKG_MGR="dpkg"
    elif command -v rpm &>/dev/null; then
        PKG_MGR="rpm"
    else
        print_warning "No supported package manager found (dpkg/rpm)"
        return
    fi

    local total=0
    if [ "$PKG_MGR" = "dpkg" ]; then
        total=$(dpkg -l 2>/dev/null | grep -c '^ii' || echo "0")
    else
        total=$(rpm -qa 2>/dev/null | wc -l)
    fi
    print_info "Package manager: $PKG_MGR  |  Total installed: $total"

    # Build installed list once for dpkg (fast lookup)
    local INSTALLED_LIST=""
    if [ "$PKG_MGR" = "dpkg" ]; then
        INSTALLED_LIST=$(dpkg -l 2>/dev/null | grep '^ii' | awk '{print $2}' | sed 's/:.*$//')
    fi

    _pkg_is_installed() {
        local pkg="$1"
        if [ "$PKG_MGR" = "dpkg" ]; then
            echo "$INSTALLED_LIST" | grep -qx "$pkg"
        else
            rpm -q "$pkg" &>/dev/null 2>&1
        fi
    }

    # --- GUI / Desktop packages ---
    print_subsection "GUI / Desktop Packages (should not be on a server)"
    local GUI_PACKAGES=(
        "xserver-xorg" "xorg" "xdm" "lightdm" "gdm3" "sddm" "lxdm"
        "gnome-shell" "gnome-session" "gnome-desktop3"
        "kde-plasma-desktop" "kde-standard" "plasma-desktop"
        "xfce4" "lxde" "lxde-core" "mate-desktop-environment"
        "cinnamon" "openbox" "i3" "xfwm4"
    )
    local gui_found=()
    for pkg in "${GUI_PACKAGES[@]}"; do
        if _pkg_is_installed "$pkg"; then
            gui_found+=("$pkg")
        fi
    done

    if [ "${#gui_found[@]}" -gt 0 ]; then
        print_warning "GUI/desktop packages found — unnecessary attack surface on a server:"
        for pkg in "${gui_found[@]}"; do echo "    $pkg"; done
    else
        print_ok "No GUI/desktop packages detected"
    fi

    # --- Compilers / Dev tools ---
    print_subsection "Compilers and Development Tools (not needed in production)"
    local DEV_PACKAGES=(
        "gcc" "gcc-12" "gcc-11" "gcc-10" "gcc-9"
        "g++" "g++-12" "g++-11" "g++-10"
        "clang" "llvm" "llvm-dev"
        "make" "cmake" "build-essential" "automake" "autoconf"
        "gdb" "strace" "ltrace" "valgrind"
        "python3-dev" "python3-pip" "python-dev"
        "ruby-dev" "ruby-build"
        "golang" "golang-go"
        "cargo" "rustc"
    )
    local dev_found=()
    for pkg in "${DEV_PACKAGES[@]}"; do
        if _pkg_is_installed "$pkg"; then
            dev_found+=("$pkg")
        fi
    done

    if [ "${#dev_found[@]}" -gt 0 ]; then
        print_warning "Compiler/dev tools found — an attacker can compile exploits directly on this machine:"
        for pkg in "${dev_found[@]}"; do echo "    $pkg"; done
    else
        print_ok "No compilers or development tools detected"
    fi

    # --- Pending security updates ---
    print_subsection "Pending Package Updates"
    if [ "$PKG_MGR" = "dpkg" ]; then
        if command -v apt-get &>/dev/null; then
            print_info "Simulating upgrade (apt-get -s upgrade)..."
            local apt_sim pending count
            apt_sim=$(apt-get -s upgrade 2>/dev/null)
            pending=$(echo "$apt_sim" | grep '^Inst' | head -20)
            count=$(echo "$apt_sim" | grep -c '^Inst')
            if [ "$count" -gt 0 ]; then
                print_bad "$count package(s) have updates available — system is not fully patched:"
                echo "$pending" | sed 's/^/    /'
                [ "$count" -gt 20 ] && echo "    ... ($count total; first 20 shown)"
            else
                print_ok "No pending package updates"
            fi
        else
            print_info "apt-get not found — cannot check for pending updates"
        fi
    else
        if command -v dnf &>/dev/null; then
            print_info "Checking security updates (dnf check-update --security)..."
            dnf check-update --security 2>/dev/null
            local dnf_exit=$?
            if [ "$dnf_exit" -eq 100 ]; then
                print_bad "Security updates are available (dnf exit code 100)"
            elif [ "$dnf_exit" -eq 0 ]; then
                print_ok "No security updates pending"
            fi
        elif command -v yum &>/dev/null; then
            print_info "Checking security updates (yum check-update --security)..."
            yum check-update --security 2>/dev/null
            [ $? -eq 100 ] && print_bad "Security updates are available"
        else
            print_info "No RPM update tool found (dnf/yum)"
        fi
    fi
}

# ============================================================
# SECTION 5: Logging
# ============================================================

check_syslog() {
    print_section "7. Syslog Daemon"

    local found=0

    if ps -edf 2>/dev/null | grep -q '[r]syslogd'; then
        found=1
        print_ok "rsyslog is running"
    fi
    if ps -edf 2>/dev/null | grep -q '[s]yslog-ng'; then
        found=1
        print_ok "syslog-ng is running"
    fi
    if ps -edf 2>/dev/null | grep -qE '[/]syslogd(\s|$)'; then
        found=1
        print_ok "syslogd (classic) is running"
    fi

    echo ""
    if [ "$found" -eq 0 ]; then
        print_bad "No syslog daemon found (rsyslog / syslog-ng / syslogd)"
        print_bad "System events are NOT being recorded — security incidents go undetected"
    fi
}

check_syslog_config() {
    print_section "8. Syslog Configuration"

    local rsyslog_conf="/etc/rsyslog.conf"
    local rsyslog_running=0
    ps -edf 2>/dev/null | grep -q '[r]syslogd' && rsyslog_running=1

    if [ "$rsyslog_running" -eq 0 ] && [ ! -f "$rsyslog_conf" ]; then
        print_info "rsyslog not active — skipping rsyslog config review"
        if [ -f /etc/syslog-ng/syslog-ng.conf ]; then
            print_subsection "syslog-ng config excerpt"
            grep -v '^\s*#' /etc/syslog-ng/syslog-ng.conf | grep -v '^\s*$' | head -30 | sed 's/^/  /'
        fi
        return
    fi

    if [ ! -f "$rsyslog_conf" ]; then
        print_warning "$rsyslog_conf not found"
        return
    fi

    print_info "Reviewing $rsyslog_conf"
    echo ""

    # --- File permission directives ---
    print_subsection "Log File Permission Settings"

    local file_owner file_group file_create_mode
    file_owner=$(grep -iP '^\s*\$FileOwner\b' "$rsyslog_conf" 2>/dev/null | awk '{print $2}' | head -1)
    file_group=$(grep -iP '^\s*\$FileGroup\b' "$rsyslog_conf" 2>/dev/null | awk '{print $2}' | head -1)
    file_create_mode=$(grep -iP '^\s*\$FileCreateMode\b' "$rsyslog_conf" 2>/dev/null | awk '{print $2}' | head -1)

    if [ -n "$file_owner" ]; then
        if [ "$file_owner" = "root" ] || [ "$file_owner" = "syslog" ]; then
            print_ok "\$FileOwner = $file_owner"
        else
            print_warning "\$FileOwner = $file_owner (expected: root or syslog)"
        fi
    else
        print_info "\$FileOwner not set — using rsyslog default"
    fi

    if [ -n "$file_group" ]; then
        if [ "$file_group" = "adm" ] || [ "$file_group" = "root" ]; then
            print_ok "\$FileGroup = $file_group"
        else
            print_warning "\$FileGroup = $file_group (expected: adm or root)"
        fi
    else
        print_info "\$FileGroup not set — using rsyslog default"
    fi

    if [ -n "$file_create_mode" ]; then
        local mode_int
        mode_int=$((8#${file_create_mode#0}))  # strip leading 0 for arithmetic
        # 0640 octal = 416 decimal; stricter means smaller or equal
        if [ "$mode_int" -le 416 ]; then
            print_ok "\$FileCreateMode = $file_create_mode (not world-readable)"
        else
            print_bad "\$FileCreateMode = $file_create_mode — log files may be world-readable"
        fi
    else
        print_warning "\$FileCreateMode not set — rsyslog default is 0644 (world-readable logs)"
    fi

    # --- Remote log forwarding ---
    print_subsection "Remote Log Forwarding"
    local remote_lines
    remote_lines=$(grep -Ev '^\s*#' "$rsyslog_conf" 2>/dev/null \
        | grep -E '^\s*(\*\.\*|[a-z]+\.\*|[a-z]+\.[a-z]+)\s+@@?' | head -10)

    # Check include directories for forwarding config
    local incl_dir_fwd=""
    while IFS= read -r incl; do
        local dir="${incl%\*}"
        [ -d "$dir" ] && incl_dir_fwd+=$(grep -rE '^\s*(\*\.\*|[a-z]+\.\*)\s+@@?' "$dir" 2>/dev/null | head -5)
    done < <(grep -oP '(?<=IncludeConfig )\S+' "$rsyslog_conf" 2>/dev/null)

    if [ -n "$remote_lines" ] || [ -n "$incl_dir_fwd" ]; then
        print_ok "Remote log forwarding is configured:"
        [ -n "$remote_lines" ]  && echo "$remote_lines"  | sed 's/^/    /'
        [ -n "$incl_dir_fwd" ]  && echo "$incl_dir_fwd" | sed 's/^/    /'
    else
        print_warning "No remote log forwarding found in rsyslog config"
        print_warning "Logs live only on this machine — an attacker with root can destroy all evidence"
        print_warning "Fix: add a line like '*.* @logserver.internal' to $rsyslog_conf"
    fi

    # --- Remote reception (informational) ---
    print_subsection "Remote Log Reception (is this server a log collector?)"
    if grep -qE '^\s*\$?ModLoad\s+imudp|^\s*module\(load="imudp"\)' "$rsyslog_conf" 2>/dev/null; then
        print_info "imudp loaded — this machine is receiving remote syslog over UDP"
    fi
    if grep -qE '^\s*\$?ModLoad\s+imtcp|^\s*module\(load="imtcp"\)' "$rsyslog_conf" 2>/dev/null; then
        print_info "imtcp loaded — this machine is receiving remote syslog over TCP"
    fi
    if ! grep -qE '^\s*\$?ModLoad\s+im(udp|tcp)|^\s*module\(load="im(udp|tcp)"\)' "$rsyslog_conf" 2>/dev/null; then
        print_info "No imudp/imtcp loaded — this server does not accept remote syslog (normal for non-collectors)"
    fi
}

check_log_permissions() {
    print_section "9. Log File Permissions"

    local LOG_FILES=(
        "/var/log/syslog"
        "/var/log/auth.log"
        "/var/log/kern.log"
        "/var/log/messages"
        "/var/log/secure"
    )
    # wtmp and lastlog are intentionally world-readable — required by last, who, w, lastlog commands
    local WORLD_READABLE_OK=(
        "/var/log/wtmp"
        "/var/log/lastlog"
    )

    local found_any=0
    for logfile in "${LOG_FILES[@]}"; do
        if [ -f "$logfile" ]; then
            found_any=1
            local perms owner group
            perms=$(stat -c '%a' "$logfile" 2>/dev/null)
            owner=$(stat -c '%U' "$logfile" 2>/dev/null)
            group=$(stat -c '%G' "$logfile" 2>/dev/null)
            local other_read=$(( 8#${perms} & 4 ))
            if [ "$other_read" -ne 0 ]; then
                print_bad "$logfile  perm=$perms owner=$owner:$group — WORLD-READABLE: any local user can read"
            else
                print_ok "$logfile  perm=$perms owner=$owner:$group"
            fi
        fi
    done
    for logfile in "${WORLD_READABLE_OK[@]}"; do
        if [ -f "$logfile" ]; then
            found_any=1
            local perms owner group
            perms=$(stat -c '%a' "$logfile" 2>/dev/null)
            owner=$(stat -c '%U' "$logfile" 2>/dev/null)
            group=$(stat -c '%G' "$logfile" 2>/dev/null)
            print_ok "$logfile  perm=$perms owner=$owner:$group (world-readable by design — needed by last/who/w)"
        fi
    done

    [ "$found_any" -eq 0 ] && print_info "None of the standard log files found in /var/log"

    # --- Journal persistence ---
    print_subsection "systemd Journal Persistence"
    if [ -d /var/log/journal ]; then
        print_ok "/var/log/journal/ exists — journal is persistent (survives reboots)"
    else
        print_warning "/var/log/journal/ not found — journal is volatile (lost on reboot)"
        local storage
        storage=$(grep -oP '(?<=^Storage=)\S+' /etc/systemd/journald.conf 2>/dev/null)
        if [ -n "$storage" ]; then
            print_info "journald.conf Storage=$storage"
        else
            print_info "journald Storage not set — defaults to 'auto' (persistent only if /var/log/journal exists)"
            print_info "To make persistent: mkdir -p /var/log/journal && systemctl restart systemd-journald"
        fi
    fi
}

# ============================================================
# Main
# ============================================================


# ============================================================
# NETWORK REVIEW FUNCTIONS
# ============================================================

check_interfaces() {
    print_section "1. Network Interfaces"
    print_info "Listing all network interfaces (ifconfig -a or ip addr show):"
    echo ""
    if command -v ifconfig &>/dev/null; then
        ifconfig -a
    else
        ip addr show
    fi
}

check_routing() {
    print_section "2. Routing Table"
    print_info "Current routing table (route -n or ip route show):"
    echo ""
    if command -v route &>/dev/null; then
        route -n
    else
        ip route show
    fi
}

check_dns() {
    print_section "3. DNS Configuration"

    print_subsection "/etc/resolv.conf"
    if [ -f /etc/resolv.conf ]; then
        cat /etc/resolv.conf
    else
        print_warning "/etc/resolv.conf not found"
    fi

    print_subsection "/etc/hosts"
    if [ -f /etc/hosts ]; then
        cat /etc/hosts
        echo ""
        # Flag entries beyond standard localhost/hostname entries
        local unexpected
        unexpected=$(grep -v '^\s*#' /etc/hosts | grep -v '^\s*$' \
            | grep -vE '^\s*(127\.|::1|fe80:|ff00:)' \
            | grep -v "$(hostname)" )
        if [ -n "$unexpected" ]; then
            print_warning "Non-standard entries in /etc/hosts (verify these are intentional):"
            echo "$unexpected" | sed 's/^/    /'
        else
            print_ok "No unexpected static host entries"
        fi
    else
        print_warning "/etc/hosts not found"
    fi

    print_subsection "/etc/nsswitch.conf"
    if [ -f /etc/nsswitch.conf ]; then
        grep -v '^\s*#' /etc/nsswitch.conf | grep -v '^\s*$'
    else
        print_warning "/etc/nsswitch.conf not found"
    fi
}

# ============================================================
# SECTION 2: Local Network Observations
# ============================================================

check_arp() {
    print_section "4. ARP Table"
    print_info "Current ARP/neighbor table:"
    echo ""
    ip neigh show
    echo ""

    # Detect duplicate MACs within the same address family.
    # fe80:: link-local entries are excluded: it is normal for a device's IPv6 link-local
    # address to share the same MAC as its IPv4 address (they are the same physical NIC).
    local dup_macs
    dup_macs=$(ip neigh show | grep -v 'fe80::' | awk '{print $5}' | grep -v '^$' | sort | uniq -d)
    if [ -n "$dup_macs" ]; then
        print_bad "Duplicate MAC address(es) detected — possible ARP poisoning:"
        echo "$dup_macs" | while read -r mac; do
            echo "    MAC $mac seen for:"
            ip neigh show | grep -v 'fe80::' | awk -v m="$mac" '$5==m {print "      " $1}'
        done
    else
        print_ok "No duplicate MAC addresses in ARP table"
    fi
}

check_promiscuous_mode() {
    print_section "5. Promiscuous Mode"
    print_info "Checking for interfaces in promiscuous mode (PROMISC flag):"
    echo ""

    local promisc_ifaces
    promisc_ifaces=$(ip link show | grep -i promisc | awk -F': ' '{print $2}' | awk '{print $1}')
    if [ -n "$promisc_ifaces" ]; then
        print_bad "Interface(s) in promiscuous mode — a packet sniffer may be active:"
        echo "$promisc_ifaces" | sed 's/^/    /'
    else
        print_ok "No interfaces in promiscuous mode"
    fi
}

# ============================================================
# SECTION 3: Firewall
# ============================================================

check_firewall_detection() {
    print_section "6. Firewall Frontend Detection"

    local found=0

    # nftables
    if command -v nft &>/dev/null; then
        local nft_output
        nft_output=$(nft list ruleset 2>/dev/null)
        if [ -n "$nft_output" ]; then
            print_warning "nftables is active with rules. Showing ruleset:"
            echo "$nft_output" | sed 's/^/  /'
            found=1
        else
            print_info "nftables is available but has no rules"
        fi
    fi

    # ufw
    if command -v ufw &>/dev/null; then
        local ufw_status
        ufw_status=$(ufw status 2>/dev/null)
        if echo "$ufw_status" | grep -q "Status: active"; then
            print_warning "ufw is active. Status:"
            echo "$ufw_status" | sed 's/^/  /'
            found=1
        else
            print_info "ufw is installed but inactive"
        fi
    fi

    # firewalld
    if command -v firewall-cmd &>/dev/null; then
        if firewall-cmd --state 2>/dev/null | grep -q "running"; then
            print_warning "firewalld is running. Active zones:"
            firewall-cmd --list-all 2>/dev/null | sed 's/^/  /'
            found=1
        else
            print_info "firewalld is installed but not running"
        fi
    fi

    if [ "$found" -eq 0 ]; then
        print_info "No high-level firewall frontend detected — relying on raw iptables"
    fi

    print_info "Note: iptables rules are always checked below regardless of frontend"
}

check_ipv4_firewall() {
    print_section "7. IPv4 Firewall Rules (iptables)"

    if ! command -v iptables &>/dev/null; then
        print_warning "iptables not found on this system"
        return
    fi

    print_info "Current iptables rules:"
    echo ""
    iptables -L -v --line-numbers 2>/dev/null
    echo ""

    # Check default policies
    local input_policy forward_policy output_policy
    input_policy=$(iptables -L INPUT 2>/dev/null | head -1 | grep -oP 'policy \K\w+')
    forward_policy=$(iptables -L FORWARD 2>/dev/null | head -1 | grep -oP 'policy \K\w+')
    output_policy=$(iptables -L OUTPUT 2>/dev/null | head -1 | grep -oP 'policy \K\w+')

    print_subsection "Policy Analysis"

    if [ "$input_policy" = "DROP" ] || [ "$input_policy" = "REJECT" ]; then
        print_ok "INPUT default policy: $input_policy (default-deny — good)"
    elif [ "$input_policy" = "ACCEPT" ]; then
        print_bad "INPUT default policy: ACCEPT — no default-deny; all unmatched traffic is allowed"
    else
        print_warning "INPUT policy could not be determined"
    fi

    if [ "$forward_policy" = "ACCEPT" ]; then
        print_warning "FORWARD default policy: ACCEPT — this machine will route packets between interfaces"
    elif [ -n "$forward_policy" ]; then
        print_ok "FORWARD default policy: $forward_policy"
    fi

    if [ "$output_policy" = "ACCEPT" ]; then
        print_warning "OUTPUT default policy: ACCEPT — no outgoing traffic restrictions (best practice is to restrict)"
    elif [ -n "$output_policy" ]; then
        print_ok "OUTPUT default policy: $output_policy"
    fi

    # Check if INPUT chain is empty (no rules at all)
    local input_rule_count
    input_rule_count=$(iptables -L INPUT 2>/dev/null | tail -n +3 | grep -c '.')
    if [ "$input_rule_count" -eq 0 ]; then
        print_bad "INPUT chain has no rules — firewall is effectively off (policy decides everything)"
    fi

    # Check if SSH (port 22) is open to the world
    print_subsection "SSH Exposure Check"
    if iptables -L INPUT -v -n 2>/dev/null | grep -qE 'dpt:22\s*(\/\*.*\*/)?\s*$|dpt:ssh\s*(\/\*.*\*/)?\s*$'; then
        # Check if it's restricted to a source IP
        local ssh_rule
        ssh_rule=$(iptables -L INPUT -v -n 2>/dev/null | grep -E 'dpt:22|dpt:ssh')
        if echo "$ssh_rule" | grep -qE '0\.0\.0\.0/0\s+0\.0\.0\.0/0|anywhere\s+anywhere'; then
            print_bad "SSH (port 22) is open to the world (0.0.0.0/0) — should be restricted to trusted IPs"
        else
            print_ok "SSH appears restricted to specific source address(es)"
        fi
    else
        print_info "No explicit SSH rule found in INPUT chain"
    fi
}

check_firewall_persistence() {
    print_section "8. Firewall Persistence"
    print_info "Checking if firewall rules survive reboot..."
    echo ""

    # Debian/Ubuntu style: if-pre-up.d hook + iptables.up.rules
    local hook_file="/etc/network/if-pre-up.d/iptables"
    local rules_file="/etc/iptables.up.rules"

    if [ -f "$hook_file" ]; then
        print_ok "Persistence hook found: $hook_file"
        echo ""
        cat "$hook_file" | sed 's/^/  /'
    else
        print_bad "No persistence hook at $hook_file — iptables rules will NOT survive reboot"
    fi

    if [ -f "$rules_file" ]; then
        print_ok "Saved rules file found: $rules_file"
        print_subsection "Saved rules ($rules_file)"
        cat "$rules_file" | sed 's/^/  /'
    else
        print_warning "No saved rules file at $rules_file"
    fi

    # Also check iptables-persistent / netfilter-persistent
    if [ -d /etc/iptables ] && ls /etc/iptables/*.rules &>/dev/null 2>&1; then
        print_ok "iptables-persistent rules directory found: /etc/iptables/"
        ls /etc/iptables/*.rules | sed 's/^/  /'
    fi

    # Diff live rules vs saved rules
    if [ -f "$rules_file" ]; then
        print_subsection "Live rules vs saved rules (diff)"
        local diff_output
        diff_output=$(diff <(iptables-save 2>/dev/null | grep -v '^#') \
                          <(grep -v '^#' "$rules_file" 2>/dev/null))
        if [ -z "$diff_output" ]; then
            print_ok "Live rules match saved rules — consistent"
        else
            print_bad "Live rules differ from saved rules — rules changed since last save:"
            echo "$diff_output" | sed 's/^/  /'
        fi
    fi
}

check_ipv6_firewall() {
    print_section "9. IPv6 Firewall (ip6tables)"

    # Check if IPv6 is disabled at kernel level
    local ipv6_disabled
    ipv6_disabled=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null)
    if [ "$ipv6_disabled" = "1" ]; then
        print_ok "IPv6 is disabled via sysctl (net.ipv6.conf.all.disable_ipv6=1)"
        return
    else
        print_info "IPv6 is enabled (net.ipv6.conf.all.disable_ipv6=$ipv6_disabled)"
    fi

    # Also check for disableipv6.conf sysctl drop-in
    if [ -f /etc/sysctl.d/disableipv6.conf ]; then
        print_info "Found /etc/sysctl.d/disableipv6.conf:"
        cat /etc/sysctl.d/disableipv6.conf | sed 's/^/  /'
    fi

    if ! command -v ip6tables &>/dev/null; then
        print_warning "ip6tables not found — cannot audit IPv6 firewall"
        return
    fi

    print_info "Current ip6tables rules:"
    echo ""
    ip6tables -L -v --line-numbers 2>/dev/null
    echo ""

    # Check if ALL chains have ACCEPT policy and zero rules
    local ip6_input_policy ip6_forward_policy ip6_output_policy
    ip6_input_policy=$(ip6tables -L INPUT 2>/dev/null | head -1 | grep -oP 'policy \K\w+')
    ip6_forward_policy=$(ip6tables -L FORWARD 2>/dev/null | head -1 | grep -oP 'policy \K\w+')
    ip6_output_policy=$(ip6tables -L OUTPUT 2>/dev/null | head -1 | grep -oP 'policy \K\w+')

    # Count rules specifically in the INPUT chain (skip the 2-line header).
    # We check INPUT because that is what protects the machine from incoming traffic.
    # Other chains (FORWARD, Docker custom chains) may have rules legitimately.
    local ip6_input_rule_count
    ip6_input_rule_count=$(ip6tables -L INPUT 2>/dev/null | tail -n +3 | grep -c '.' || true)

    if [ "$ip6_input_policy" = "ACCEPT" ] && [ "$ip6_input_rule_count" -eq 0 ]; then
        print_bad "IPv6 is enabled but ip6tables INPUT has no rules and policy is ACCEPT"
        print_bad "All IPv6 input traffic is permitted — the IPv4 firewall is completely bypassed via IPv6"
        print_info "Fix: apply equivalent rules with ip6tables, or disable IPv6 via sysctl"
    else
        if [ "$ip6_input_policy" = "DROP" ] || [ "$ip6_input_policy" = "REJECT" ]; then
            print_ok "IPv6 INPUT default policy: $ip6_input_policy"
        else
            print_warning "IPv6 INPUT default policy: $ip6_input_policy"
        fi
    fi
}

# ============================================================
# SECTION 4: Kernel Network Parameters (sysctl)
# ============================================================

check_sysctl_network() {
    print_section "10. Kernel Network Parameters (sysctl)"
    print_info "Comparing current values against secure baseline:"
    echo ""

    # Format: ["parameter"]="expected_value|risk_description"
    declare -A SYSCTL_CHECKS
    SYSCTL_CHECKS["net.ipv4.ip_forward"]="0|Enables IP routing between interfaces; bypasses FORWARD firewall"
    SYSCTL_CHECKS["net.ipv4.conf.all.accept_redirects"]="0|Accepts ICMP redirects; allows MITM traffic rerouting"
    SYSCTL_CHECKS["net.ipv4.conf.default.accept_redirects"]="0|Same as accept_redirects for new interfaces"
    SYSCTL_CHECKS["net.ipv4.conf.all.send_redirects"]="0|Server sends ICMP redirects; only routers should do this"
    SYSCTL_CHECKS["net.ipv4.conf.all.accept_source_route"]="0|Allows sender to specify packet path; bypasses firewall rules"
    SYSCTL_CHECKS["net.ipv4.tcp_syncookies"]="1|Without SYN cookies, SYN flood DoS exhausts connection table"
    SYSCTL_CHECKS["net.ipv4.conf.all.rp_filter"]="1|Disables reverse path filtering; allows IP spoofing"
    SYSCTL_CHECKS["net.ipv4.icmp_echo_ignore_broadcasts"]="1|Without this, server amplifies smurf DoS attacks"
    SYSCTL_CHECKS["net.ipv4.conf.all.log_martians"]="1|Spoofed/impossible packets go unlogged"
    SYSCTL_CHECKS["net.ipv6.conf.all.accept_redirects"]="0|IPv6 ICMP redirect MITM (same risk as IPv4)"
    SYSCTL_CHECKS["net.ipv6.conf.all.accept_source_route"]="0|IPv6 source routing bypass (same risk as IPv4)"

    local all_ok=1
    for param in "${!SYSCTL_CHECKS[@]}"; do
        local entry="${SYSCTL_CHECKS[$param]}"
        local expected="${entry%%|*}"
        local risk="${entry##*|}"
        local actual
        actual=$(sysctl -n "$param" 2>/dev/null)
        if [ -z "$actual" ]; then
            print_warning "$param — not available on this kernel"
        elif [ "$actual" = "$expected" ]; then
            print_ok "$param = $actual"
        else
            print_bad "$param = $actual (expected $expected)"
            echo -e "         ${RED}Risk: $risk${NC}"
            all_ok=0
        fi
    done

    echo ""
    if [ "$all_ok" -eq 1 ]; then
        print_ok "All checked sysctl network parameters are at secure values"
    fi
}

# ============================================================
# SECTION 5: TCP Wrappers
# ============================================================

check_tcp_wrappers() {
    print_section "11. TCP Wrappers"
    print_info "TCP Wrappers provide application-level access control independent of iptables."
    echo ""

    local has_allow has_deny
    has_allow=0
    has_deny=0

    if [ -f /etc/hosts.allow ]; then
        has_allow=1
        print_subsection "/etc/hosts.allow"
        grep -v '^\s*#' /etc/hosts.allow | grep -v '^\s*$' | sed 's/^/  /' || echo "  (empty)"
    else
        print_warning "/etc/hosts.allow not found"
    fi

    if [ -f /etc/hosts.deny ]; then
        has_deny=1
        print_subsection "/etc/hosts.deny"
        grep -v '^\s*#' /etc/hosts.deny | grep -v '^\s*$' | sed 's/^/  /' || echo "  (empty)"
    else
        print_warning "/etc/hosts.deny not found"
    fi

    echo ""
    if [ "$has_allow" -eq 0 ] && [ "$has_deny" -eq 0 ]; then
        print_warning "TCP Wrappers not configured — no hosts.allow or hosts.deny present"
    elif [ "$has_deny" -eq 0 ]; then
        print_warning "No hosts.deny — connections not denied by default in TCP Wrappers"
    elif grep -qE '^\s*ALL\s*:\s*ALL' /etc/hosts.deny 2>/dev/null; then
        print_ok "hosts.deny has 'ALL: ALL' — default-deny in TCP Wrappers"
    else
        print_warning "hosts.deny exists but does not have 'ALL: ALL' — not default-deny"
    fi
}

# ============================================================
# SECTION 6: Network Services
# ============================================================

check_listening_services() {
    print_section "12. Listening Services (Open Ports)"
    print_info "Services listening on the network. Flag: anything bound to 0.0.0.0 / * / :: (all interfaces)."
    echo ""

    if command -v ss &>/dev/null; then
        print_subsection "TCP Listening (ss -tlnp)"
        ss -tlnp
        echo ""
        print_subsection "UDP Listening (ss -ulnp)"
        ss -ulnp
    elif command -v lsof &>/dev/null; then
        print_info "ss not available, falling back to lsof"
        print_subsection "TCP Listening (lsof -i TCP -n -P)"
        lsof -i TCP -n -P | grep LISTEN
        echo ""
        print_subsection "UDP Listening (lsof -i UDP -n -P)"
        lsof -i UDP -n -P
    else
        print_warning "Neither ss nor lsof available — cannot enumerate listening services"
        return
    fi

    echo ""
    print_subsection "Exposure Analysis"

    # Detect services listening on all interfaces via ss
    if command -v ss &>/dev/null; then
        # Services on 0.0.0.0 or * or :: (all interfaces)
        local exposed
        exposed=$(ss -tlnp | awk 'NR>1 && ($4 ~ /^0\.0\.0\.0:/ || $4 ~ /^\*:/ || $4 ~ /^:::/)' )
        if [ -n "$exposed" ]; then
            print_warning "TCP services listening on ALL interfaces (verify each is intentionally public):"
            echo "$exposed" | sed 's/^/  /'
        else
            print_ok "No TCP services listening on all interfaces"
        fi

        local exposed_udp
        exposed_udp=$(ss -ulnp | awk 'NR>1 && ($4 ~ /^0\.0\.0\.0:/ || $4 ~ /^\*:/ || $4 ~ /^:::/)' )
        if [ -n "$exposed_udp" ]; then
            print_warning "UDP services listening on ALL interfaces:"
            echo "$exposed_udp" | sed 's/^/  /'
        fi
    fi
}

check_active_connections() {
    print_section "13. Active Network Connections"
    print_info "Currently established connections. Review for unexpected outbound connections."
    echo ""

    if command -v ss &>/dev/null; then
        print_subsection "Established TCP connections (ss -antp | grep ESTABLISHED)"
        local established
        established=$(ss -antp | grep ESTABLISHED)
        if [ -n "$established" ]; then
            echo "$established" | sed 's/^/  /'
            echo ""
            # Flag connections where the remote port is a low/well-known port (server connecting outbound)
            local outbound
            outbound=$(echo "$established" | awk '{print $5}' | grep -oP '(?<=:)\d+$' | awk '$1 < 1024')
            if [ -n "$outbound" ]; then
                print_warning "Outbound connections to well-known ports detected (remote port < 1024):"
                echo "$established" | while read -r line; do
                    local rport
                    rport=$(echo "$line" | awk '{print $5}' | grep -oP '(?<=:)\d+$')
                    if [ -n "$rport" ] && [ "$rport" -lt 1024 ] 2>/dev/null; then
                        echo "  $line"
                    fi
                done
            fi
        else
            print_ok "No established TCP connections at time of scan"
        fi
    elif command -v netstat &>/dev/null; then
        print_subsection "Established connections (netstat -antp)"
        netstat -antp | grep ESTABLISHED | sed 's/^/  /'
    else
        print_warning "Neither ss nor netstat available"
    fi
}

# ============================================================
# Main
# ============================================================


# ============================================================
# FILESYSTEM REVIEW FUNCTIONS
# ============================================================

check_mounts() {

    print_section "1. Mounted Partitions"

    print_subsection "Mounted Filesystems"

    findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS

    echo ""

    while read -r line; do

        [[ "$line" =~ ^#.*$ ]] && continue
        [[ -z "$line" ]] && continue

        mountpoint=$(echo "$line" | awk '{print $2}')
        options=$(echo "$line" | awk '{print $4}')

        [ -z "$mountpoint" ] && continue

        print_info "Reviewing $mountpoint"

        # ----------------------------------------------------
        # noatime
        # ----------------------------------------------------

        if echo "$options" | grep -qw noatime; then
            print_bad "$mountpoint uses noatime"
            print_bad "Access timestamps are NOT recorded"
            print_bad "This weakens forensic investigations"
        else
            print_ok "$mountpoint does not use noatime"
        fi

        # ----------------------------------------------------
        # /tmp
        # ----------------------------------------------------

        if [ "$mountpoint" = "/tmp" ]; then

            if echo "$options" | grep -qw noexec; then
                print_ok "/tmp uses noexec"
            else
                print_warning "/tmp does NOT use noexec"
                print_warning "Attackers may execute binaries from /tmp"
            fi

            if echo "$options" | grep -qw nosuid; then
                print_ok "/tmp uses nosuid"
            else
                print_warning "/tmp does NOT use nosuid"
            fi

            if echo "$options" | grep -qw nodev; then
                print_ok "/tmp uses nodev"
            else
                print_warning "/tmp does NOT use nodev"
            fi
        fi

        # ----------------------------------------------------
        # /home
        # ----------------------------------------------------

        if [ "$mountpoint" = "/home" ]; then

            if echo "$options" | grep -qw nosuid; then
                print_ok "/home uses nosuid"
            else
                print_warning "/home does NOT use nosuid"
            fi

            if echo "$options" | grep -qw noexec; then
                print_ok "/home uses noexec"
            else
                print_info "/home does not use noexec"
            fi
        fi

        # ----------------------------------------------------
        # /dev
        # ----------------------------------------------------

        if [ "$mountpoint" = "/dev" ]; then

            if echo "$options" | grep -qw nosuid; then
                print_ok "/dev uses nosuid"
            else
                print_warning "/dev does NOT use nosuid"
            fi
        fi

        echo ""

    done < /etc/fstab
}

# ============================================================
# SECTION 2: Sensitive Files
# ============================================================

check_sensitive_files() {

    print_section "2. Sensitive Files"

    # ========================================================
    # SENSITIVE SYSTEM FILES
    # ========================================================

    print_subsection "Sensitive System Files"

    local files=(
        "/etc/shadow"
        "/etc/gshadow"
        "/etc/mysql/my.cnf"
    )

    local problems=0

    for file in "${files[@]}"; do

        [ ! -f "$file" ] && continue

        local perms owner
        perms=$(stat -c "%a" "$file" 2>/dev/null)
        owner=$(stat -c "%U" "$file" 2>/dev/null)

        # Last digit = permissions for "others"
        local other=$(( perms % 10 ))

        local other_read=$(( other & 4 ))
        local other_write=$(( other & 2 ))

        local issue_found=0

        # ----------------------------------------------------
        # World-readable
        # ----------------------------------------------------

        if [ "$other_read" -ne 0 ]; then
            print_bad "$file owner=$owner perm=$perms -> WORLD-READABLE"
            issue_found=1
            ((problems++))
        fi

        # ----------------------------------------------------
        # World-writable
        # ----------------------------------------------------

        if [ "$other_write" -ne 0 ]; then
            print_bad "$file owner=$owner perm=$perms -> WORLD-WRITABLE"
            issue_found=1
            ((problems++))
        fi

        # ----------------------------------------------------
        # Wrong owner
        # ----------------------------------------------------

        if [ "$owner" != "root" ]; then
            print_warning "$file owner is '$owner' instead of root"
            issue_found=1
            ((problems++))
        fi

        # ----------------------------------------------------
        # Safe
        # ----------------------------------------------------

        if [ "$issue_found" -eq 0 ]; then
            print_ok "$file owner=$owner perm=$perms"
        fi
    done

    if [ "$problems" -eq 0 ]; then
        print_ok "Sensitive system file permissions look safe"
    fi

    # ========================================================
    # BACKUPS OF SENSITIVE FILES
    # ========================================================

    print_subsection "Sensitive Backup Files"

    local backup_found=0

    while read -r backup; do

        [ -z "$backup" ] && continue

        local perms owner
        perms=$(stat -c "%a" "$backup" 2>/dev/null)
        owner=$(stat -c "%U" "$backup" 2>/dev/null)

        local other=$(( perms % 10 ))
        local other_read=$(( other & 4 ))

        if [ "$other_read" -ne 0 ]; then
            print_bad "$backup owner=$owner perm=$perms -> WORLD-READABLE BACKUP"
            backup_found=1
        fi

    done < <(
        find /etc \
            -type f \
            \( \
                -iname "shadow*" \
                -o -iname "*.bak" \
                -o -iname "*.backup" \
            \) \
            2>/dev/null
    )

    if [ "$backup_found" -eq 0 ]; then
        print_ok "No dangerous world-readable sensitive backups found"
    fi
}

# ============================================================
# SECTION 3: SUID Files
# ============================================================

check_suid() {

    print_section "3. SUID Files"

    print_info "Searching for SUID binaries..."

    find / \
    -perm -4000 \
    -type f \
    ! -path "/snap/*" \
    ! -path "/var/lib/docker/*" \
    ! -path "/proc/*" \
    ! -path "/sys/*" \
    2>/dev/null | while read -r line; do

        file=$(echo "$line" | awk '{print $NF}')

        owner=$(stat -c "%U" "$file" 2>/dev/null)

        if [ "$owner" = "root" ]; then
            print_warning "Root SUID binary: $file"
        else
            print_info "Non-root SUID binary: $file"
        fi
    done
}

# ============================================================
# SECTION 4: World Writable Files
# ============================================================

check_world_writable() {

    print_section "4. World Writable / Readable Files"

    local paths=(
        "/etc"
        "/usr/bin"
        "/usr/sbin"
        "/root"
        "/home"
        "/var/www"
        "/opt"
    )

    print_subsection "World Readable + Writable (Sensitive Locations)"

    for path in "${paths[@]}"; do
        find "$path" \
            \( \
                -path "/proc" -o \
                -path "/sys" -o \
                -path "/dev" -o \
                -path "*/snap/*" -o \
                -path "/var/lib/docker/*" -o \
                -path "*/.cache/*" -o \
                -path "*/.config/Code/User/History/*" -o \
                -path "*/node_modules/*" \
            \) -prune -o \
            -type f -perm -006 -print 2>/dev/null | while read -r file; do

            print_bad "$file is world-readable and world-writable (SENSITIVE LOCATION)"
        done
    done

    print_subsection "World Writable Files (Sensitive Locations)"

    for path in "${paths[@]}"; do
        find "$path" \
            \( \
                -path "/proc" -o \
                -path "/sys" -o \
                -path "/dev" -o \
                -path "*/snap/*" -o \
                -path "/var/lib/docker/*" -o \
                -path "*/.cache/*" -o \
                -path "*/.config/Code/User/History/*" -o \
                -path "*/node_modules/*" \
            \) -prune -o \
            -type f -perm -002 -print 2>/dev/null | while read -r file; do

            print_warning "$file is world-writable (SENSITIVE LOCATION)"
        done
    done
}

# ============================================================
# SECTION 5: Backup Files
# ============================================================

check_backups() {

    print_section "5. Backup Files"

    local backup_dirs=(
        "/etc"
        "/var/backups"
        "/backup"
        "/root"
    )

    local found=0

    print_subsection "Sensitive Backup Files (System Locations Only)"

    for dir in "${backup_dirs[@]}"; do

        [ ! -d "$dir" ] && continue

        while IFS= read -r file; do

            [ -z "$file" ] && continue

            perms=$(stat -c "%a" "$file" 2>/dev/null)
            owner=$(stat -c "%U" "$file" 2>/dev/null)

            [ -z "$perms" ] && continue

            # only REAL backup exposure check
            if [ $((perms % 10 & 4)) -ne 0 ]; then
                print_bad "Sensitive backup exposed: $file (owner=$owner perm=$perms)"
                found=1
            fi

        done < <(
            find "$dir" -type f \( \
                -iname "*.bak" -o \
                -iname "*.backup" -o \
                -iname "*.old" \
            \) 2>/dev/null
        )

    done

    if [ "$found" -eq 0 ]; then
        print_ok "No exposed sensitive backups found in system locations"
    fi
}

# ============================================================
# Main
# ============================================================


# ============================================================
# USERS REVIEW FUNCTIONS
# ============================================================

check_users() {

    print_section "6. Users and Shell Access"

    # ========================================================
    # UID 0 USERS
    # ========================================================

    print_subsection "Users With UID 0 (Root Privileges)"

    local uid0_found=0

    while IFS=: read -r user x uid gid comment home shell; do

        if [ "$uid" -eq 0 ]; then

            uid0_found=1

            if [ "$user" = "root" ]; then
                print_ok "root has UID 0"
            else
                print_bad "$user has UID 0 -> FULL ROOT PRIVILEGES"
            fi
        fi

    done < /etc/passwd

    if [ "$uid0_found" -eq 0 ]; then
        print_warning "No UID 0 users found"
    fi

    # ========================================================
    # USERS WITH LOGIN SHELL
    # ========================================================

    print_subsection "Users With Interactive Shell Access"

    local shell_found=0

    while IFS=: read -r user x uid gid comment home shell; do

        case "$shell" in
            */bash|*/sh|*/zsh|*/fish|*/ksh)

                shell_found=1

                if [ "$uid" -lt 1000 ] && [ "$user" != "root" ]; then
                    print_warning "$user has shell access ($shell) [SYSTEM USER]"
                else
                    print_info "$user -> $shell"
                fi
            ;;
        esac

    done < /etc/passwd

    if [ "$shell_found" -eq 0 ]; then
        print_ok "No users with interactive shells found"
    fi
}

# ============================================================
# SECTION 2: Password Hash Algorithms
# ============================================================

check_password_hashes() {

    print_section "7. Password Hash Algorithms"

    print_subsection "Reviewing /etc/shadow Hash Formats"

    local weak_found=0

    while IFS=: read -r user hash rest; do

        # skip locked / disabled accounts
        [[ "$hash" == "!"* || "$hash" == "*" || -z "$hash" ]] && continue

        algo="UNKNOWN"

        if [[ "$hash" != \$* ]]; then
            algo="DES"
            print_bad "$user uses DES hash"
            weak_found=1

        elif [[ "$hash" == \$1\$* ]]; then
            algo="MD5"
            print_bad "$user uses MD5 hash"
            weak_found=1

        elif [[ "$hash" == \$2* ]]; then
            algo="Blowfish/bcrypt"
            print_ok "$user uses $algo"

        elif [[ "$hash" == \$5\$* ]]; then
            algo="SHA-256"
            print_ok "$user uses SHA-256"

        elif [[ "$hash" == \$6\$* ]]; then
            algo="SHA-512"
            print_ok "$user uses SHA-512"

        elif [[ "$hash" == \$y\$* ]]; then
            algo="yescrypt"
            print_ok "$user uses yescrypt"

        else
            print_warning "$user uses unknown hash format"
        fi

    done < /etc/shadow

    if [ "$weak_found" -eq 0 ]; then
        print_ok "No weak password hash algorithms detected"
    fi

    # ========================================================
    # DEFAULT PASSWORD HASH ALGORITHM
    # ========================================================

    print_subsection "Default Password Algorithm"

    if grep -qi yescrypt /etc/pam.d/common-password 2>/dev/null; then
        print_ok "System default password algorithm: yescrypt"

    elif grep -qi sha512 /etc/pam.d/common-password 2>/dev/null; then
        print_ok "System default password algorithm: SHA-512"

    elif grep -qi md5 /etc/pam.d/common-password 2>/dev/null; then
        print_bad "System default password algorithm: MD5"

    else
        print_warning "Could not determine default password algorithm"
    fi

    # ========================================================
    # PASSWORD COMPLEXITY POLICY
    # ========================================================

    print_subsection "Password Complexity Policy"

    if grep -Eq "pam_cracklib|pam_pwquality" /etc/pam.d/common-password 2>/dev/null; then

        print_ok "Password complexity module enabled"

        grep -E "pam_cracklib|pam_pwquality" /etc/pam.d/common-password 2>/dev/null

    else
        print_warning "No password complexity policy detected"
        print_warning "Weak passwords may be accepted"
    fi
}

# ============================================================
# SECTION 3: Sudo Configuration
# ============================================================

check_sudo_config() {

    print_section "8. Sudo Configuration"

    print_subsection "Reviewing sudo Rules"

    local dangerous_found=0

    while read -r line; do

        [ -z "$line" ] && continue

        print_info "$line"

        # ----------------------------------------------------
        # NOPASSWD
        # ----------------------------------------------------

        if echo "$line" | grep -q "NOPASSWD"; then
            print_bad "NOPASSWD detected -> sudo without password"
            dangerous_found=1
        fi

        # ----------------------------------------------------
        # ALL=(ALL) ALL
        # ----------------------------------------------------

        if echo "$line" | grep -q "ALL=(ALL) ALL"; then
            print_warning "User/group has FULL sudo access"
        fi

        # ----------------------------------------------------
        # Dangerous commands
        # ----------------------------------------------------

        if echo "$line" | grep -Eq "/bin/chown|/bin/chmod|/bin/bash|/bin/sh|/usr/bin/vim|/usr/bin/nano|/usr/bin/find|/usr/bin/python|/usr/bin/perl"; then

            print_bad "Potential privilege escalation command allowed"
            dangerous_found=1
        fi

    done < <(
        egrep -v '^#|^$' /etc/sudoers 2>/dev/null
    )

    # ========================================================
    # Included sudoers.d files
    # ========================================================

    if [ -d /etc/sudoers.d ]; then

        print_subsection "Reviewing /etc/sudoers.d"

        while read -r file; do

            [ -z "$file" ] && continue

            print_info "Reviewing $file"

            while read -r line; do

                [ -z "$line" ] && continue

                print_info "$line"

                if echo "$line" | grep -q "NOPASSWD"; then
                    print_bad "NOPASSWD detected in $file"
                    dangerous_found=1
                fi

            done < <(
                egrep -v '^#|^$' "$file" 2>/dev/null
            )

        done < <(
            find /etc/sudoers.d -type f 2>/dev/null
        )
    fi

    # ========================================================
    # Final result
    # ========================================================

    if [ "$dangerous_found" -eq 0 ]; then
        print_ok "No dangerous sudo misconfigurations detected"
    fi
}


# ============================================================
# SERVICE REVIEW FUNCTIONS
# ============================================================

ISSUES=0
inc_issues() { ISSUES=$((ISSUES + 1)); }

run_service_review() {

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
  else
    info "MySQL config file not found — MySQL may not be installed or uses different path"
  fi

  echo ""
  info "After making any MySQL config changes, restart the service:"
  detail "systemctl restart mysql   (or: service mysql restart)"

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
}

# ============================================================
# Main
# ============================================================

main() {

    echo -e "${BOLD}${BLUE}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║          LINUX SECURITY REVIEW SCRIPT                ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "  Host:    $(hostname)"
    echo -e "  Date:    $(date)"
    echo -e "  User:    $(id)"
    echo ""

    check_root

    # ── System Review ──────────────────────────────────────────
    echo -e "\n${BOLD}${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${BLUE}║              SYSTEM REVIEW                           ║${NC}"
    echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════╝${NC}"

    check_os
    check_kernel
    check_kernel_cves
    check_timezone
    check_ntp
    check_packages
    check_syslog
    check_syslog_config
    check_log_permissions

    echo ""
    echo -e "${BOLD}${BLUE}════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE}  System review complete.${NC}"
    echo -e "${BOLD}${BLUE}════════════════════════════════════════${NC}"

    # ── Network Review ─────────────────────────────────────────
    echo -e "\n${BOLD}${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${BLUE}║              NETWORK REVIEW                          ║${NC}"
    echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════╝${NC}"

    check_interfaces
    check_routing
    check_dns
    check_arp
    check_promiscuous_mode
    check_firewall_detection
    check_ipv4_firewall
    check_firewall_persistence
    check_ipv6_firewall
    check_sysctl_network
    check_tcp_wrappers
    check_listening_services
    check_active_connections

    echo ""
    echo -e "${BOLD}${BLUE}════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE}  Network review complete.${NC}"
    echo -e "${BOLD}${BLUE}════════════════════════════════════════${NC}"

    # ── Filesystem Review ──────────────────────────────────────
    echo -e "\n${BOLD}${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${BLUE}║              FILESYSTEM REVIEW                       ║${NC}"
    echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════╝${NC}"

    check_mounts
    check_sensitive_files
    check_suid
    check_world_writable
    check_backups

    echo ""
    echo -e "${BOLD}${BLUE}════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE}  Filesystem review complete.${NC}"
    echo -e "${BOLD}${BLUE}════════════════════════════════════════${NC}"

    # ── Users Review ───────────────────────────────────────────
    echo -e "\n${BOLD}${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${BLUE}║              USERS REVIEW                            ║${NC}"
    echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════╝${NC}"

    check_users
    check_password_hashes
    check_sudo_config

    echo ""
    echo -e "${BOLD}${BLUE}════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE}  Users review complete.${NC}"
    echo -e "${BOLD}${BLUE}════════════════════════════════════════${NC}"

    # ── Services Review ────────────────────────────────────────
    echo -e "\n${BOLD}${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${BLUE}║              SERVICES REVIEW                         ║${NC}"
    echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════╝${NC}"
    echo -e "  Host: $(hostname)   Date: $(date)"
    echo -e "  User: $(whoami)     Kernel: $(uname -r)\n"

    run_service_review

    echo ""
    echo -e "${BOLD}${BLUE}════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE}  Services review complete.${NC}"
    echo -e "${BOLD}${BLUE}════════════════════════════════════════${NC}"

    echo ""
    echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${BLUE}║         SECURITY REVIEW COMPLETE                     ║${NC}"
    echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
}

main "$@"
