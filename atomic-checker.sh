#!/usr/bin/env bash
#
# atomic-checker — AUR & npm package vulnerability checker
#
# Usage:
#   atomic-checker -a aurvulnlist.txt    -n npmvulnlist.txt
#   atomic-checker -a pkg1,pkg2,pkg3    -n atomic-lockfile,nextfile-js
#

set -euo pipefail

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Check installed AUR and npm packages against vulnerability lists.

  -a, --aur FILE|LIST    AUR package list: path to .txt file or comma-separated names
  -n, --npm FILE|LIST    npm package list: path to .txt file or comma-separated names
  -h, --help             Show this help and exit

Examples:
  $(basename "$0") -a aurvulnlist.txt -n npmvulnlist.txt
  $(basename "$0") -a fontfinder,qt5-3d -n atomic-lockfile,nextfile-js
EOF
}

die() { echo "Error: $*" >&2; exit 1; }

parse_list() {
    local input="$1"
    if [[ -f "$input" ]]; then
        # Read from file, strip line numbers (e.g. "1: foo") and whitespace
        sed 's/^[0-9]*: //' "$input" | sed 's/^ *//;s/ *$//' | grep -v '^$' | sort -u
    else
        # Comma-separated list
        echo "$input" | tr ',' '\n' | sed 's/^ *//;s/ *$//' | grep -v '^$' | sort -u
    fi
}

# ---------------------------------------------------------------------------
# AUR check (pacman)
# ---------------------------------------------------------------------------

check_aur() {
    local input="$1"
    local list tmpfile found
    list=$(parse_list "$input")
    [[ -z "$list" ]] && { echo "No AUR packages to check."; return 0; }

    tmpfile=$(mktemp)
    echo "$list" > "$tmpfile"

    echo "=== AUR Package Check ==="
    found=$(pacman -Qq 2>/dev/null | grep -Fxf "$tmpfile" || true)
    if [[ -n "$found" ]]; then
        echo "Installed packages found:"
        echo "$found" | while read -r pkg; do
            local info
            info=$(pacman -Qi "$pkg" 2>/dev/null | grep -E "^(Name|Version|Description|Install Date|Install Reason|Required By)" || true)
            echo ""
            echo "  ── $pkg ──"
            echo "$info" | sed 's/^/    /'
        done
    else
        echo "No matching AUR packages installed."
    fi
    rm -f "$tmpfile"
    echo ""
}

# ---------------------------------------------------------------------------
# npm check
# ---------------------------------------------------------------------------

check_npm() {
    local input="$1"
    local list tmpfile found
    list=$(parse_list "$input")
    [[ -z "$list" ]] && { echo "No npm packages to check."; return 0; }

    tmpfile=$(mktemp)
    echo "$list" > "$tmpfile"

    echo "=== npm Package Check ==="
    found=""

    # 1. Check global npm packages
    if command -v npm &>/dev/null; then
        local global_pkgs
        global_pkgs=$(npm list -g --depth=0 2>/dev/null | grep -v "(empty)" || true)
        if [[ -n "$global_pkgs" ]]; then
            while read -r pkg; do
                local pat pkgbase
                pkgbase=$(basename "$pkg")
                pat=$(grep -Fxm1 "$pkgbase" "$tmpfile" || true)
                if [[ -n "$pat" ]]; then
                    found="${found}${pkgbase}\n"
                fi
            done < <(echo "$list")
        fi
    fi

    # 2. Check all node_modules directories on the system
    while read -r dir; do
        while read -r pkg; do
            if [[ -d "$dir/$pkg" ]]; then
                found="${found}${pkg} (node_modules: $dir/$pkg)\n"
            fi
        done < "$tmpfile"
    done < <(find / -path /proc -prune -o -path /run -prune -o -path /tmp -prune -o -name "node_modules" -type d -print 2>/dev/null)

    # 3. Check package.json references
    while read -r json; do
        while read -r pkg; do
            if grep -q "\"$pkg\"" "$json" 2>/dev/null; then
                found="${found}${pkg} (package.json: $json)\n"
            fi
        done < "$tmpfile"
    done < <(find / -path /proc -prune -o -path /run -prune -o -path /tmp -prune -o -name "package.json" -type f -print 2>/dev/null)

    if [[ -n "$found" ]]; then
        echo "Installed/referenced packages found:"
        echo -e "$found" | sort -u | sed 's/^/  /'
    else
        echo "No matching npm packages found."
    fi
    rm -f "$tmpfile"
    echo ""
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    local aur_input="" npm_input=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -a|--aur)
                shift
                aur_input="${1:-}"
                [[ -z "$aur_input" ]] && die "Option $1 requires a value."
                ;;
            -n|--npm)
                shift
                npm_input="${1:-}"
                [[ -z "$npm_input" ]] && die "Option $1 requires a value."
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                die "Unknown option: $1"
                ;;
        esac
        shift
    done

    if [[ -z "$aur_input" && -z "$npm_input" ]]; then
        usage
        exit 1
    fi

    if [[ -n "$aur_input" ]]; then
        check_aur "$aur_input"
    fi

    if [[ -n "$npm_input" ]]; then
        check_npm "$npm_input"
    fi
}

main "$@"
