# atomic-checker

Two-step package checker for AUR and npm packages. Validates installed packages on an Arch Linux system against vulnerability lists.

## Features

- **AUR check**: Compares installed pacman packages against a list
- **npm check — two phases**:
  - **Phase 1 (Quick)**: Global npm installs, common `node_modules` paths, and `package.json` references
  - **Phase 2 (Deep)**: Optional full-filesystem scan for any `node_modules` directory
- **Sudo integration**: Phase 2 asks for sudo to scan system-wide paths (e.g. `/root`, `/var`, `/opt`)
- **Safe exclusions**: Always skips `/proc`, `/run`, `/sys`, `/dev`, `/tmp` to avoid kernel filesystem errors
- **Gum support**: If [charmbracelet/gum](https://github.com/charmbracelet/gum) is installed and a TTY is available, prompts are interactive and pretty; otherwise falls back to plain bash
- **Flexible input**: Accepts either a `.txt` file or comma-separated package names
- **Clean output**: Shows installed matches with metadata (version, install date, etc.)

## Usage

```bash
# Text files
./atomic-checker.sh -a aurvulnlist.txt -n npmvulnlist.txt

# Comma-separated names
./atomic-checker.sh -a fontfinder,qt5-3d -n atomic-lockfile,nextfile-js

# Mixed (one file, one list)
./atomic-checker.sh -a aurvulnlist.txt -n atomic-lockfile,nextfile-js
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

## License

MIT
