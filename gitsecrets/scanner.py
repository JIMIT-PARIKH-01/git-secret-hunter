"""
Git-history secret scanner.

Walks a repository's ENTIRE commit history (all branches) and flags secrets in
every version of every file -- so it catches credentials that were committed and
later "removed" but still live in history (and are therefore still leaked).

Drives the system `git` binary; pure standard library otherwise.
"""

from __future__ import annotations

import subprocess
from collections import defaultdict
from dataclasses import dataclass, field

from .patterns import PATTERNS

# Skip obviously-binary / vendored paths to cut noise.
_SKIP = (".min.js", ".lock", "package-lock.json", "yarn.lock", ".map",
         ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".woff", ".ttf")


@dataclass
class Leak:
    commit: str
    author: str
    date: str
    file: str
    rule: str
    excerpt: str


@dataclass
class ScanResult:
    repo: str
    commits_scanned: int = 0
    leaks: list = field(default_factory=list)

    def by_rule(self) -> dict:
        groups = defaultdict(list)
        for leak in self.leaks:
            groups[leak.rule].append(leak)
        return groups

    def as_text(self) -> str:
        lines = [f"=== git-history secret scan: {self.repo} ===",
                 f"Commits scanned : {self.commits_scanned}",
                 f"Secrets found   : {len(self.leaks)}"]
        if not self.leaks:
            lines.append("No secrets found in history. ✓")
            return "\n".join(lines)
        for rule, items in sorted(self.by_rule().items(), key=lambda kv: -len(kv[1])):
            lines.append(f"\n[{rule}]  ({len(items)} occurrence(s))")
            for leak in items[:20]:
                lines.append(f"  {leak.commit}  {leak.date}  {leak.file}")
                lines.append(f"      {leak.excerpt}")
        lines.append("\n! These secrets remain in git history even if deleted from current"
                     " files. Rotate them, and consider rewriting history (git filter-repo).")
        return "\n".join(lines)


def _git(repo: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", repo, *args],
                          capture_output=True, text=True, errors="replace")


def scan_repo(repo: str, max_commits: int | None = None) -> ScanResult:
    if _git(repo, "rev-parse", "--is-inside-work-tree").returncode != 0:
        raise ValueError(f"'{repo}' is not a git repository")

    fmt = "\x01%h\x02%an\x02%ad"
    args = ["log", "--all", "-p", "--no-color", "--date=short", f"--pretty=format:{fmt}"]
    if max_commits:
        args += ["-n", str(max_commits)]
    out = _git(repo, *args).stdout

    result = ScanResult(repo=repo)
    seen = set()
    commit = author = date = cur_file = ""
    for line in out.splitlines():
        if line.startswith("\x01"):
            parts = line[1:].split("\x02")
            commit = parts[0]
            author = parts[1] if len(parts) > 1 else ""
            date = parts[2] if len(parts) > 2 else ""
            cur_file = ""
            result.commits_scanned += 1
            continue
        if line.startswith("+++ b/"):
            cur_file = line[6:]
            continue
        if line.startswith("+") and not line.startswith("+++"):
            if cur_file.endswith(_SKIP):
                continue
            content = line[1:]
            for rule, rx in PATTERNS.items():
                m = rx.search(content)
                if m:
                    key = (rule, m.group(0))
                    if key in seen:
                        continue
                    seen.add(key)
                    result.leaks.append(Leak(commit, author, date, cur_file, rule,
                                             content.strip()[:100]))
    return result
