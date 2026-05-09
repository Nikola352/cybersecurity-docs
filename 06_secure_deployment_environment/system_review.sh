#!/bin/bash
# system_review.sh - System configuration security review
# Part of a linpeas-inspired system hardening audit tool.
# Requires root. Uses only LOTL (living-off-the-land) system commands.
# CVE lookups use the NVD (NIST) API v2.0 — internet access required for that section.

# ============================================================
# Color definitions
# ============================================================
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

print_section()   { echo -e "\n${BOLD}${BLUE}════════════════════════════════════════${NC}"; \
                    echo -e "${BOLD}${BLUE}  $1${NC}"; \
                    echo -e "${BOLD}${BLUE}════════════════════════════════════════${NC}"; }
print_subsection(){ echo -e "\n${BOLD}--- $1 ---${NC}"; }
print_ok()        { echo -e "  ${GREEN}[OK]${NC}   $1"; }
print_warning()   { echo -e "  ${YELLOW}[WARN]${NC} $1"; }
print_bad()       { echo -e "  ${RED}[BAD]${NC}  $1"; }
print_info()      { echo -e "  ${BOLD}[*]${NC}   $1"; }

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

main() {
    echo -e "${BOLD}${BLUE}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║            SYSTEM SECURITY REVIEW SCRIPT             ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "  Host:    $(hostname)"
    echo -e "  Date:    $(date)"
    echo -e "  User:    $(id)"
    echo ""

    check_root

    # Section 1: Operating System (includes OS CVE lookup)
    check_os

    # Section 2: Kernel
    check_kernel
    check_kernel_cves

    # Section 3: Time Management
    check_timezone
    check_ntp

    # Section 4: Installed Packages
    check_packages

    # Section 5: Logging
    check_syslog
    check_syslog_config
    check_log_permissions

    echo ""
    echo -e "${BOLD}${BLUE}════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE}  System review complete.${NC}"
    echo -e "${BOLD}${BLUE}════════════════════════════════════════${NC}"
    echo ""
}

main
