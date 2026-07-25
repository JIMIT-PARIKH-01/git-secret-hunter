"""git-secret-hunter -- scan a git repo's full commit history for leaked secrets."""

from . import scanner, patterns

__version__ = "1.0.0"
__all__ = ["scanner", "patterns"]
