# atomic-checker

Two-step package checker for AUR and npm packages. Validates installed packages on an Arch Linux system against vulnerability lists.

## Why this exists

Supply-chain attacks are increasingly targeting package ecosystems. In the Arch Linux AUR, orphaned packages are especially vulnerable because they have no active maintainer. A compromised orphaned package can be hijacked by a malicious actor to inject backdoors or malware into systems.

**Source of compromised AUR orphaned packages:**

- [Arch Linux Wiki — Compromised AUR Orphaned Packages](https://md.archlinux.org/s/SxbqukK6IA#)

This is one of the resources you can use to populate your vulnerability list (`-a` flag).

## npm packages of concern

This tool was originally built to check for the following **npm packages** that were flagged as suspicious or malicious:

- `atomic-lockfile`
- `nextfile-js`
- `js-digest`
- `lockfile-js`

These packages were identified as part of an investigation into potentially malicious npm packages that use generic names related to core Node.js concepts (lockfiles, file systems, digests) to trick developers into installing them. The concern is that they may contain backdoors, data exfiltration logic, or other malicious behavior. Always verify packages before installing them, especially when they have low download counts or no verifiable maintainer.

## Features

- **AUR check**: Compares currently installed pacman packages against a list
- **Optional AUR history check**: Scans `/var/log/pacman.log` for `installed`, `upgraded`, `reinstalled`, `downgraded`, and `removed` events
- **Optional AUR helper cache check**: Looks for matching traces in `yay` and `paru` cache directories, including `PKGBUILD` and `.SRCINFO`
- **Optional build trace check**: Looks for package directories, `PKGBUILD`, `.SRCINFO`, tarballs, and cached package artifacts in common build/cache paths
- **npm check — two phases**:
  - **Phase 1 (Quick)**: Global npm installs, common `node_modules` paths, and `package.json` references
  - **Phase 2 (Deep)**: Optional full-filesystem scan for any `node_modules` directory
- **Sudo integration**: npm Phase 2 asks for sudo to scan system-wide paths (e.g. `/root`, `/var`, `/opt`) when needed
- **Safe exclusions**: npm deep scan always skips `/proc`, `/run`, `/sys`, `/dev`, `/tmp` to avoid kernel filesystem errors
- **Gum support**: If [charmbracelet/gum](https://github.com/charmbracelet/gum) is installed and a TTY is available, prompts are interactive and pretty; otherwise falls back to plain bash
- **Flexible input**: Accepts either a `.txt` file or comma-separated package names
- **Clean output**: Separates current matches, historical matches, helper-cache traces, and build-trace findings

## Scope

For AUR package names, the script now distinguishes between different kinds of evidence:

- **Current state**: package is installed right now
- **History**: package appeared in `pacman.log` even if it is no longer installed
- **Helper cache traces**: package remnants exist in `yay`/`paru` caches
- **Build traces**: local build leftovers or cached artifacts still exist

The script does **not** inspect filesystem snapshots or backup stores.

## Usage

```bash
# Text files
./atomic-checker.sh -a aurvulnlist.txt -n npmvulnlist.txt

# Comma-separated names
./atomic-checker.sh -a fontfinder,qt5-3d -n atomic-lockfile,nextfile-js

# Mixed (one file, one list)
./atomic-checker.sh -a aurvulnlist.txt -n atomic-lockfile,nextfile-js
```

When an AUR list is provided, the script first runs the current installed-package check.
After that, it offers three optional follow-up checks with short explanations:

1. `pacman.log` history scan
2. `yay`/`paru` cache trace scan
3. build trace and cached artifact scan

These optional checks are intended for historical or forensic follow-up, not just current installed state.

If you want to skip the prompts and force any of those checks, use these flags:

- `--check-history`
- `--check-cache`
- `--check-build-traces`

Example:

```bash
./atomic-checker.sh -a aurvulnlist.txt --check-history --check-cache --check-build-traces
```

## Input format

**Text files** — one package per line. Supports numbered lines (`1: foo`):
```
fontfinder
qt5-3d
atomic-lockfile
```

**Comma-separated** — inline list:
```bash
-a fontfinder,qt5-3d
```

## Requirements

- `bash`
- `pacman` (for AUR check)
- `npm` (for npm global check)
- `find` and `grep` (standard utilities)
- `gum` (optional, for pretty interactive prompts)
- `sudo` (optional, for deep system-wide npm scan when required by unreadable directories)

## License

MIT
