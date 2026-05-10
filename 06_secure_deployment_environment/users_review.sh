#!/bin/bash
# users_review.sh
# Users and file-permission security review
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

print_section() {
    echo -e "\n${BOLD}${BLUE}════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE}  $1${NC}"
    echo -e "${BOLD}${BLUE}════════════════════════════════════════${NC}"
}

print_subsection() {
    echo -e "\n${BOLD}--- $1 ---${NC}"
}

print_ok() {
    echo -e "  ${GREEN}[OK]${NC}   $1"
}

print_warning() {
    echo -e "  ${YELLOW}[WARN]${NC} $1"
}

print_bad() {
    echo -e "  ${RED}[BAD]${NC}  $1"
}

print_info() {
    echo -e "  ${BOLD}[*]${NC}   $1"
}


# ============================================================
# SECTION 1: Users and Shell Access
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

check_sudo() {

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

main() {

    echo -e "${BOLD}${BLUE}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║          USERS SECURITY REVIEW SCRIPT          ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    echo -e "  Host: $(hostname)"
    echo -e "  Date: $(date)"
    echo -e "  User: $(id)"
    echo ""

    check_users
    check_password_hashes
    check_sudo

    echo ""
    echo -e "${BOLD}${BLUE}════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE}  Users review complete.${NC}"
    echo -e "${BOLD}${BLUE}════════════════════════════════════════${NC}"
}

main