"""Regex fingerprints for common secrets (used by the history scanner)."""

from __future__ import annotations

import re

PATTERNS = {
    "AWS Access Key ID": re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS Secret Key": re.compile(r"(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),
    "Private key block": re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    "Google API key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Slack token": re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    "Slack webhook": re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}"),
    "GitHub token": re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}"),
    "GitHub fine-grained token": re.compile(r"github_pat_[0-9A-Za-z_]{40,}"),
    "Stripe secret key": re.compile(r"sk_(?:live|test)_[0-9A-Za-z]{24,}"),
    "Twilio SID": re.compile(r"AC[0-9a-fA-F]{32}"),
    "SendGrid key": re.compile(r"SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}"),
    "JWT": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "Generic API key/secret": re.compile(
        r"(?i)(api[_-]?key|apikey|secret|access[_-]?token)\s*[:=]\s*['\"][0-9A-Za-z\-_]{16,}['\"]"),
    "Hard-coded password": re.compile(
        r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]"),
    "Connection string password": re.compile(r"(?i)://[^:/\s]+:[^@/\s]{4,}@"),
}
