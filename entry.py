"""Entry point for building the standalone executable with PyInstaller.

Usage:
    pyinstaller --onefile --name akar entry.py

The regular CLI is unaffected: `python -m akar` / the `akar` console script
both call `akar.cli:main` directly.
"""

from akar.cli import main

if __name__ == "__main__":
    main()
