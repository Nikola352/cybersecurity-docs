#!/bin/bash
# filesystem_review.sh
# Filesystem and file-permission security review
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
# Root check
# ============================================================

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}[!] Run as root for complete results${NC}"
        exit 1
    fi
}

# ============================================================
# SECTION 1: Mounted Partitions
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

    local ignore_regex="^/proc/|^/sys/|^/dev/|/snap/|/var/lib/docker/|/home/.*/\.cache/|/home/.*/\.config/Code/User/History/"

    print_subsection "World Readable + Writable (Sensitive Locations)"

    for path in "${paths[@]}"; do
        find "$path" -type f -perm -006 2>/dev/null | while read -r file; do

            [[ "$file" =~ $ignore_regex ]] && continue

            print_bad "$file is world-readable and world-writable (SENSITIVE LOCATION)"
        done
    done

    print_subsection "World Writable Files (Sensitive Locations)"

    for path in "${paths[@]}"; do
        find "$path" -type f -perm -002 2>/dev/null | while read -r file; do

            [[ "$file" =~ $ignore_regex ]] && continue

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

main() {

    echo -e "${BOLD}${BLUE}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║          FILESYSTEM SECURITY REVIEW SCRIPT          ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    echo -e "  Host: $(hostname)"
    echo -e "  Date: $(date)"
    echo -e "  User: $(id)"
    echo ""

    check_root

    check_mounts
    check_sensitive_files
    check_suid
    check_world_writable
    check_backups

    echo ""
    echo -e "${BOLD}${BLUE}════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE}  Filesystem review complete.${NC}"
    echo -e "${BOLD}${BLUE}════════════════════════════════════════${NC}"
}

main