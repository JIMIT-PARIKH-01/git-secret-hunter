"""Entry point:  python -m gitsecrets [repo] [--max N] [--exit-code]"""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
