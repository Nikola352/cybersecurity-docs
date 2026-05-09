#!/bin/bash
# network_review.sh - Network configuration security review
# Part of a linpeas-inspired system hardening audit tool.
# Requires root. Uses only LOTL (living-off-the-land) system commands.

# ============================================================
# Color definitions
# ============================================================
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

print_section()  { echo -e "\n${BOLD}${BLUE}════════════════════════════════════════${NC}"; \
                   echo -e "${BOLD}${BLUE}  $1${NC}"; \
                   echo -e "${BOLD}${BLUE}════════════════════════════════════════${NC}"; }
print_subsection(){ echo -e "\n${BOLD}--- $1 ---${NC}"; }
print_ok()       { echo -e "  ${GREEN}[OK]${NC}   $1"; }
print_warning()  { echo -e "  ${YELLOW}[WARN]${NC} $1"; }
print_bad()      { echo -e "  ${RED}[BAD]${NC}  $1"; }
print_info()     { echo -e "  ${BOLD}[*]${NC}   $1"; }

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
# SECTION 1: General Network Information
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

main() {
    echo -e "${BOLD}${BLUE}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║           NETWORK SECURITY REVIEW SCRIPT             ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "  Host:    $(hostname)"
    echo -e "  Date:    $(date)"
    echo -e "  User:    $(id)"
    echo ""

    check_root

    # Section 1: General network info
    check_interfaces
    check_routing
    check_dns

    # Section 2: Local network observations
    check_arp
    check_promiscuous_mode

    # Section 3: Firewall
    check_firewall_detection
    check_ipv4_firewall
    check_firewall_persistence
    check_ipv6_firewall

    # Section 4: Kernel parameters
    check_sysctl_network

    # Section 5: TCP Wrappers
    check_tcp_wrappers

    # Section 6: Network services
    check_listening_services
    check_active_connections

    echo ""
    echo -e "${BOLD}${BLUE}════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE}  Network review complete.${NC}"
    echo -e "${BOLD}${BLUE}════════════════════════════════════════${NC}"
    echo ""
}

main
