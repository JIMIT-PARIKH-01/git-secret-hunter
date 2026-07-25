"""
git-secret-hunter -- scan a git repo's ENTIRE history for leaked secrets.

    python -m gitsecrets                 # scan the repo in the current directory
    python -m gitsecrets /path/to/repo
    python -m gitsecrets . --max 500     # only the 500 most recent commits
    python -m gitsecrets . --exit-code   # exit 1 if any secret found (CI/pre-commit)
"""

from __future__ import annotations

import argparse
import sys

from . import scanner


def main(argv: list | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="git-secret-hunter",
        description="Find secrets across a git repo's full commit history.")
    p.add_argument("repo", nargs="?", default=".", help="Path to the git repo (default: .).")
    p.add_argument("--max", type=int, default=None, help="Scan only the N most recent commits.")
    p.add_argument("--exit-code", action="store_true",
                   help="Exit 1 if any secret is found (use in CI / pre-commit hooks).")
    args = p.parse_args(argv)

    try:
        result = scanner.scan_repo(args.repo, max_commits=args.max)
    except (ValueError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    print(result.as_text())
    return 1 if (args.exit_code and result.leaks) else 0


if __name__ == "__main__":
    raise SystemExit(main())
