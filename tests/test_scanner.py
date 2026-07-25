"""Tests for the git-history secret scanner."""

import subprocess

import pytest

from gitsecrets import scanner, patterns


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=True)


def _init(repo):
    _git(repo, "init")
    _git(repo, "config", "user.email", "t@t.test")
    _git(repo, "config", "user.name", "tester")


def test_finds_secret_still_in_history_after_removal(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    _init(repo)
    # commit a hard-coded AWS key
    (repo / "config.py").write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "add config")
    # later "fix": remove the secret from the current file
    (repo / "config.py").write_text('AWS_KEY = os.environ["AWS_KEY"]\n')
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "move secret to env")

    result = scanner.scan_repo(str(repo))
    assert result.commits_scanned >= 2
    assert any("AWS Access Key ID" == leak.rule for leak in result.leaks)
    # the leak is attributed to the file and remains discoverable
    assert any("config.py" in leak.file for leak in result.leaks)


def test_clean_repo_has_no_leaks(tmp_path):
    repo = tmp_path / "clean"
    repo.mkdir()
    _init(repo)
    (repo / "app.py").write_text("print('hello world')\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "init")
    result = scanner.scan_repo(str(repo))
    assert result.leaks == []


def test_non_repo_raises(tmp_path):
    with pytest.raises(ValueError):
        scanner.scan_repo(str(tmp_path))


def test_private_key_pattern():
    assert patterns.PATTERNS["Private key block"].search("-----BEGIN RSA PRIVATE KEY-----")


def test_deduplicates_same_secret(tmp_path):
    repo = tmp_path / "d"
    repo.mkdir()
    _init(repo)
    key = 'token = "ghp_' + "a" * 36 + '"\n'
    (repo / "a.py").write_text(key)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "one")
    (repo / "b.py").write_text(key)          # same secret, different file
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "two")
    result = scanner.scan_repo(str(repo))
    gh = [leak for leak in result.leaks if leak.rule == "GitHub token"]
    assert len(gh) == 1                       # de-duplicated by secret value
