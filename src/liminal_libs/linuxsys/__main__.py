"""`python -I -B -m liminal_libs.linuxsys`: the root command (cli.py). main() runs only when this is run as the
program, since tests/test_imports.py imports every module of the library."""
from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
