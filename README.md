# atomic-checker

Two-step package checker for AUR and npm packages. Validates installed packages on an Arch Linux system against vulnerability lists.

## Features

- **AUR check**: Compares installed pacman packages against a list
- **npm check**: Searches for npm packages in global installs, `node_modules`, and `package.json` references
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

## License

MIT
