#!/usr/bin/env bash
#
# atomic-checker — AUR & npm package vulnerability checker
#
# Usage:
#   atomic-checker -a aurvulnlist.txt    -n npmvulnlist.txt
#   atomic-checker -a pkg1,pkg2,pkg3    -n atomic-lockfile,nextfile-js
#

set -euo pipefail

FORCE_HISTORY_CHECK=false
FORCE_CACHE_CHECK=false
FORCE_BUILD_TRACE_CHECK=false

# ---------------------------------------------------------------------------
# Gum detection (optional, for pretty prompts)
# ---------------------------------------------------------------------------

USE_GUM=false
if command -v gum &>/dev/null && [ -t 0 ] && [ -t 1 ]; then
    # Test if gum can actually work in this environment
    if gum style "test" &>/dev/null; then
        USE_GUM=true
    fi
fi

# ---------------------------------------------------------------------------
# Pretty helpers
# ---------------------------------------------------------------------------

info()    { $USE_GUM && gum style --foreground 39  "$1" || echo "ℹ $1"; }
warn()    { $USE_GUM && gum style --foreground 214 "$1" || echo "⚠ $1"; }
success() { $USE_GUM && gum style --foreground 82  "$1" || echo "✔ $1"; }
error()   { $USE_GUM && gum style --foreground 196 "$1" || echo "✖ $1"; }
header()  { $USE_GUM && gum style --bold --foreground 212 "$1" || echo "=== $1 ==="; }

confirm() {
    local prompt="$1"
    if $USE_GUM; then
        gum confirm "$prompt"
    else
        read -r -p "$prompt [y/N] " ans
        [[ "$ans" =~ ^[Yy]$ ]]
    fi
}

input() {
    local prompt="$1" placeholder="${2:-}"
    if $USE_GUM; then
        gum input --placeholder "$placeholder" --prompt "$prompt "
    else
        read -r -p "$prompt: " val
        echo "$val"
    fi
}

# ---------------------------------------------------------------------------
# Usage / parse
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Check installed AUR and npm packages against vulnerability lists.

  -a, --aur FILE|LIST    AUR package list: path to .txt file or comma-separated names
  -n, --npm FILE|LIST    npm package list: path to .txt file or comma-separated names
      --check-history     Run the optional pacman.log history check without prompting
      --check-cache       Run the optional yay/paru cache check without prompting
      --check-build-traces
                         Run the optional build-trace check without prompting
  -h, --help             Show this help and exit

Examples:
  $(basename "$0") -a aurvulnlist.txt -n npmvulnlist.txt
  $(basename "$0") -a fontfinder,qt5-3d -n atomic-lockfile,nextfile-js
  $(basename "$0") -a aurvulnlist.txt --check-history --check-cache
EOF
}

die() { error "$*"; exit 1; }

parse_list() {
    local input="$1"
    if [[ -f "$input" ]]; then
        sed 's/^[0-9]*: //' "$input" | sed 's/^ *//;s/ *$//' | grep -v '^$' | sort -u
    else
        echo "$input" | tr ',' '\n' | sed 's/^ *//;s/ *$//' | grep -v '^$' | sort -u
    fi
}

join_existing_roots() {
    local root joined=""
    for root in "$@"; do
        [[ -d "$root" ]] || continue
        joined+="${root}"$'\n'
    done
    printf '%s' "$joined"
}

# ---------------------------------------------------------------------------
# AUR check (pacman)
# ---------------------------------------------------------------------------

check_aur() {
    local input="$1"
    local list tmpfile found
    list=$(parse_list "$input")
    [[ -z "$list" ]] && { info "No AUR packages to check."; return 0; }

    tmpfile=$(mktemp)
    echo "$list" > "$tmpfile"

    header "AUR Package Check"
    found=$(pacman -Qq 2>/dev/null | grep -Fxf "$tmpfile" || true)
    if [[ -n "$found" ]]; then
        warn "Installed packages found:"
        echo "$found" | while read -r pkg; do
            local info
            info=$(pacman -Qi "$pkg" 2>/dev/null | grep -E "^(Name|Version|Description|Install Date|Install Reason|Required By)" || true)
            echo ""
            echo "  ── $pkg ──"
            echo "$info" | sed 's/^/    /'
        done
    else
        success "No matching AUR packages installed."
    fi
    rm -f "$tmpfile"
    echo ""

    check_pacman_history "$input"
    check_aur_helper_cache "$input"
    check_build_traces "$input"
}

check_pacman_history() {
    local input="$1"
    local list tmpfile pkg matches any_found=false
    local log_file="/var/log/pacman.log"

    [[ -r "$log_file" ]] || {
        warn "Skipping pacman.log history check: $log_file is not readable."
        echo ""
        return 0
    }

    header "AUR History Check (pacman.log)"
    info "This optional check looks for install, upgrade, reinstall, downgrade, or removal history."
    info "Useful for packages that are no longer installed but were present recently."
    echo ""

    if ! $FORCE_HISTORY_CHECK && ! confirm "Check pacman.log for package history?"; then
        info "pacman.log history check skipped by user."
        echo ""
        return 0
    fi

    list=$(parse_list "$input")
    [[ -z "$list" ]] && { info "No AUR packages to check."; echo ""; return 0; }

    tmpfile=$(mktemp)
    echo "$list" > "$tmpfile"

    while read -r pkg; do
        matches=$(awk -v pkg="$pkg" '
            index($0, "] installed " pkg " (") ||
            index($0, "] upgraded " pkg " (") ||
            index($0, "] reinstalled " pkg " (") ||
            index($0, "] downgraded " pkg " (") ||
            index($0, "] removed " pkg " (")
        ' "$log_file" 2>/dev/null)

        if [[ -n "$matches" ]]; then
            any_found=true
            echo ""
            echo "  ── $pkg ──"
            echo "$matches" | sed 's/^/    /'
        fi
    done < "$tmpfile"

    if ! $any_found; then
        success "No matching pacman.log history entries found."
    fi

    rm -f "$tmpfile"
    echo ""
}

check_aur_helper_cache() {
    local input="$1"
    local list tmpfile pkg root matches any_found=false
    local helper_roots

    header "AUR Helper Cache Check"
    info "This optional check looks for cached package directories and AUR metadata in yay/paru caches."
    info "Useful to detect cloned or cached remnants even when a package is not installed."
    echo ""

    if ! $FORCE_CACHE_CHECK && ! confirm "Check yay/paru caches for package traces?"; then
        info "AUR helper cache check skipped by user."
        echo ""
        return 0
    fi

    list=$(parse_list "$input")
    [[ -z "$list" ]] && { info "No AUR packages to check."; echo ""; return 0; }

    helper_roots=$(join_existing_roots \
        "$HOME/.cache/yay" \
        "$HOME/.cache/paru" \
        /var/cache/yay \
        /var/cache/paru
    )

    if [[ -z "$helper_roots" ]]; then
        info "No yay/paru cache directories found."
        echo ""
        return 0
    fi

    tmpfile=$(mktemp)
    echo "$list" > "$tmpfile"

    while read -r pkg; do
        matches=""
        while read -r root; do
            [[ -n "$root" ]] || continue
            if [[ -d "$root/$pkg" ]]; then
                matches+="cache dir: $root/$pkg"$'\n'
            fi
            while read -r meta; do
                [[ -n "$meta" ]] || continue
                matches+="metadata: $meta"$'\n'
            done < <(find "$root" -path "*/$pkg/PKGBUILD" -o -path "*/$pkg/.SRCINFO" 2>/dev/null)
        done < <(printf '%s\n' "$helper_roots")

        if [[ -n "$matches" ]]; then
            any_found=true
            echo ""
            echo "  ── $pkg ──"
            echo "$matches" | awk 'NF && !seen[$0]++' | sed 's/^/    /'
        fi
    done < "$tmpfile"

    if ! $any_found; then
        success "No matching traces found in yay/paru caches."
    fi

    rm -f "$tmpfile"
    echo ""
}

check_build_traces() {
    local input="$1"
    local list tmpfile pkg root matches any_found=false
    local build_roots

    header "AUR Build Trace Check"
    info "This optional check looks for build leftovers like PKGBUILDs, .SRCINFO files, tarballs, or cached package artifacts."
    info "Useful to detect local build traces even when nothing is installed now."
    echo ""

    if ! $FORCE_BUILD_TRACE_CHECK && ! confirm "Check build traces and cached artifacts?"; then
        info "Build trace check skipped by user."
        echo ""
        return 0
    fi

    list=$(parse_list "$input")
    [[ -z "$list" ]] && { info "No AUR packages to check."; echo ""; return 0; }

    build_roots=$(join_existing_roots \
        "$HOME/.cache" \
        "$HOME/Downloads" \
        "$HOME/Projects" \
        "$HOME/dev" \
        /tmp \
        /var/tmp \
        /var/cache/pacman/pkg
    )

    tmpfile=$(mktemp)
    echo "$list" > "$tmpfile"

    while read -r pkg; do
        matches=""
        while read -r root; do
            [[ -n "$root" ]] || continue
            if [[ -d "$root/$pkg" ]]; then
                matches+="dir: $root/$pkg"$'\n'
            fi
            while read -r trace; do
                [[ -n "$trace" ]] || continue
                matches+="trace: $trace"$'\n'
            done < <(find "$root" \( \
                -path "*/$pkg" -o \
                -path "*/$pkg/PKGBUILD" -o \
                -path "*/$pkg/.SRCINFO" -o \
                -name "$pkg*.pkg.tar*" -o \
                -name "$pkg*.tar" -o \
                -name "$pkg*.tar.gz" -o \
                -name "$pkg*.tgz" -o \
                -name "$pkg*.zip" \
            \) 2>/dev/null)
        done < <(printf '%s\n' "$build_roots")

        if [[ -n "$matches" ]]; then
            any_found=true
            echo ""
            echo "  ── $pkg ──"
            echo "$matches" | awk 'NF && !seen[$0]++' | sed 's/^/    /'
        fi
    done < "$tmpfile"

    if ! $any_found; then
        success "No matching build traces or cached artifacts found."
    fi

    rm -f "$tmpfile"
    echo ""
}

# ---------------------------------------------------------------------------
# npm check — two-phase
# ---------------------------------------------------------------------------

check_npm() {
    local input="$1"
    local list tmpfile found
    list=$(parse_list "$input")
    [[ -z "$list" ]] && { info "No npm packages to check."; return 0; }

    tmpfile=$(mktemp)
    echo "$list" > "$tmpfile"

    header "npm Package Check (Phase 1: Quick)"
    found=""

    # 1. Global npm packages
    if command -v npm &>/dev/null; then
        local global_pkgs
        global_pkgs=$(npm list -g --depth=0 --parseable 2>/dev/null | while read -r p; do
            basename "$p"
        done | grep -v '^lib$' | grep -v '^node_modules$' || true)
        if [[ -n "$global_pkgs" ]]; then
            while read -r installed; do
                local pat
                pat=$(grep -Fxm1 "$installed" "$tmpfile" || true)
                if [[ -n "$pat" ]]; then
                    found="${found}${installed} (npm global)\n"
                fi
            done < <(echo "$global_pkgs")
        fi
    fi

    # 2. Common local paths
    for base in "$HOME/.npm-global" "$HOME/.local" "$HOME/Projects" "$HOME/work" /usr/lib/node_modules /opt; do
        [[ -d "$base" ]] || continue
        while read -r dir; do
            while read -r pkg; do
                if [[ -d "$dir/$pkg" ]]; then
                    found="${found}${pkg} (node_modules: $dir/$pkg)\n"
                fi
            done < "$tmpfile"
        done < <(find "$base" -name "node_modules" -type d 2>/dev/null)
    done

    # 3. package.json references (fast paths)
    while read -r json; do
        while read -r pkg; do
            if grep -q "\"$pkg\"" "$json" 2>/dev/null; then
                found="${found}${pkg} (package.json: $json)\n"
            fi
        done < "$tmpfile"
    done < <(find /home /opt /usr -path /proc -prune -o -path /run -prune -o -name "package.json" -type f -print 2>/dev/null)

    # Deduplicate & display Phase 1
    if [[ -n "$found" ]]; then
        warn "Installed/referenced packages found (Phase 1):"
        echo -e "$found" | awk -F' ' '{if(!seen[$1]++) print}' | sed 's/^/  /'
    else
        success "No matching npm packages found in Phase 1 (global + common paths)."
    fi
    echo ""

    # Phase 2 — deep system scan (optional)
    header "npm Package Check (Phase 2: Deep system scan)"
    info "This scan searches the entire filesystem for node_modules directories."
    info "It will skip pseudo-filesystems: /proc, /run, /sys, /dev, /tmp"
    info "to avoid errors and keep the scan fast."
    echo ""

    if confirm "Run deep system scan?"; then
        local deep_found=""
        local need_sudo=false

        # Check if we need sudo for directories the user can't read
        if ! find / -maxdepth 1 -type d -readable 2>/dev/null | grep -q '^/root$'; then
            need_sudo=true
        fi

        if $need_sudo; then
            info "Some directories require elevated privileges to read."
            info "Sudo is needed to scan system-wide paths (e.g. /root, /var, /opt)."
            info "/proc and /run are always excluded to avoid kernel filesystem errors."
            echo ""
            if confirm "Run scan with sudo?"; then
                echo ""
                warn "Running: sudo find / -path /proc -prune -o -path /run -prune -o -path /sys -prune -o -path /dev -prune -o -path /tmp -prune -o -name node_modules -type d -print"
                echo ""
                while read -r dir; do
                    while read -r pkg; do
                        if [[ -d "$dir/$pkg" ]]; then
                            deep_found="${deep_found}${pkg} (node_modules: $dir/$pkg)\n"
                        fi
                    done < "$tmpfile"
                done < <(sudo find / -path /proc -prune -o -path /run -prune -o -path /sys -prune -o -path /dev -prune -o -path /tmp -prune -o -name "node_modules" -type d -print 2>/dev/null)
            else
                info "Skipping sudo scan. Scanning only user-readable paths..."
                while read -r dir; do
                    while read -r pkg; do
                        if [[ -d "$dir/$pkg" ]]; then
                            deep_found="${deep_found}${pkg} (node_modules: $dir/$pkg)\n"
                        fi
                    done < "$tmpfile"
                done < <(find / -path /proc -prune -o -path /run -prune -o -path /sys -prune -o -path /dev -prune -o -path /tmp -prune -o -name "node_modules" -type d -print 2>/dev/null)
            fi
        else
            while read -r dir; do
                while read -r pkg; do
                    if [[ -d "$dir/$pkg" ]]; then
                        deep_found="${deep_found}${pkg} (node_modules: $dir/$pkg)\n"
                    fi
                done < "$tmpfile"
            done < <(find / -path /proc -prune -o -path /run -prune -o -path /sys -prune -o -path /dev -prune -o -path /tmp -prune -o -name "node_modules" -type d -print 2>/dev/null)
        fi

        # Filter out already-found packages to only show NEW ones
        local new_found=""
        while read -r line; do
            local pkg_name
            pkg_name=$(echo "$line" | awk '{print $1}')
            if ! echo -e "$found" | grep -q "^${pkg_name} "; then
                new_found="${new_found}${line}\n"
            fi
        done < <(echo -e "$deep_found" | awk -F' ' '{if(!seen[$1]++) print}' | grep -v '^$')

        if [[ -n "$new_found" ]]; then
            warn "New matches found in deep scan:"
            echo -e "$new_found" | sed 's/^/  /'
        else
            if [[ -n "$deep_found" ]]; then
                success "Deep scan completed. No new matches beyond Phase 1."
            else
                success "Deep scan completed. No additional matches found."
            fi
        fi
    else
        info "Deep scan skipped by user."
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
            --check-history)
                FORCE_HISTORY_CHECK=true
                ;;
            --check-cache)
                FORCE_CACHE_CHECK=true
                ;;
            --check-build-traces)
                FORCE_BUILD_TRACE_CHECK=true
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
