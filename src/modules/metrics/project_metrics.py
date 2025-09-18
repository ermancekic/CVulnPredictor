"""
project_metrics.py

Git-based project/file history metrics.

Implements project/file history metrics per file (tracked with git --follow):
- NumChanges:  number of commits that touched the file since creation
- LinesChanged: cumulative added + deleted lines across all touching commits
- LinesNew:  cumulative added lines across all touching commits
- NumDevs: number of distinct authors (by email) who touched the file

These functions are imported and called from modules.calculate_metrics.
"""

from __future__ import annotations

import os
import subprocess
from typing import Tuple
from functools import lru_cache


@lru_cache(maxsize=8192)
def _find_git_root(path: str) -> str | None:
    """Return the repository root (dir containing .git) for a given file/dir path.

    Walks upward from the given path until a directory with a .git entry is found.
    Returns None if no repository root can be located.
    """
    p = os.path.abspath(path)
    if os.path.isfile(p):
        p = os.path.dirname(p)
    prev = None
    while p and p != prev:
        if os.path.isdir(os.path.join(p, ".git")) or os.path.isfile(os.path.join(p, ".git")):
            return p
        prev, p = p, os.path.dirname(p)
    return None


def _git_run(repo_root: str, args: list[str]) -> str:
    """Run a git command in repo_root and return stdout (UTF-8, errors ignored)."""
    result = subprocess.run(
        ["git", *args],
        cwd=repo_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="ignore",
        check=False,
    )
    return result.stdout or ""


@lru_cache(maxsize=131072)
def _numstat_totals(repo_root: str, rel_path: str) -> Tuple[int, int, int]:
    """Return (num_changes, total_added, total_deleted) for file history.

    Uses `git log --follow --numstat` and sums only numeric numstat lines.
    """
    # Count commits touching the file (with --follow for renames)
    commits_out = _git_run(repo_root, [
        "log", "--follow", "--format=%H", "--", rel_path
    ])
    commit_count = sum(1 for line in commits_out.splitlines() if line.strip())

    # Collect per-commit added/deleted lines
    numstat_out = _git_run(repo_root, [
        "log", "--follow", "--numstat", "--format=", "--", rel_path
    ])

    total_added = 0
    total_deleted = 0
    for line in numstat_out.splitlines():
        # Expected format: "<added>\t<deleted>\t<path>"
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        a, d = parts[0].strip(), parts[1].strip()
        if not (a.isdigit() and d.isdigit()):
            # binary diff or unparsable, skip
            continue
        total_added += int(a)
        total_deleted += int(d)

    return commit_count, total_added, total_deleted


@lru_cache(maxsize=131072)
def _rel_to_root(repo_root: str, file_path: str) -> str:
    try:
        return os.path.relpath(os.path.abspath(file_path), repo_root)
    except Exception:
        return file_path


@lru_cache(maxsize=131072)
def _authors_count(repo_root: str, rel_path: str) -> int:
    """Return number of unique authors (by email, case-insensitive) for a file history.

    Uses `git log --follow` to traverse history across renames and collects `%ae` (author email).
    Non-empty emails are lowercased and deduplicated.
    """
    out = _git_run(repo_root, [
        "log", "--follow", "--format=%ae", "--", rel_path
    ])
    emails = set()
    for line in out.splitlines():
        e = (line or "").strip().lower()
        if e:
            emails.add(e)
    return len(emails)


def calculate_num_changes(file_path: str) -> int:
    """Number of commits that touched the file since its creation (git --follow)."""
    root = _find_git_root(file_path)
    if not root:
        return 0
    rel = _rel_to_root(root, file_path)
    n, _a, _d = _numstat_totals(root, rel)
    return n


def calculate_lines_changed(file_path: str) -> int:
    """Cumulated number of code lines changed (added + deleted) since creation."""
    root = _find_git_root(file_path)
    if not root:
        return 0
    rel = _rel_to_root(root, file_path)
    _n, a, d = _numstat_totals(root, rel)
    return a + d


def calculate_lines_new(file_path: str) -> int:
    """Cumulated number of new code lines (added) since creation."""
    root = _find_git_root(file_path)
    if not root:
        return 0
    rel = _rel_to_root(root, file_path)
    _n, a, _d = _numstat_totals(root, rel)
    return a


def calculate_num_devs(file_path: str) -> int:
    """Number of distinct authors (unique emails) who changed the file."""
    root = _find_git_root(file_path)
    if not root:
        return 0
    rel = _rel_to_root(root, file_path)
    return _authors_count(root, rel)


def calculate_file_project_metrics(file_path: str) -> dict:
    """Convenience helper returning all three metrics for a file path."""
    return {
        "NumChanges": calculate_num_changes(file_path),
        "LinesChanged": calculate_lines_changed(file_path),
        "LinesNew": calculate_lines_new(file_path),
        "NumDevs": calculate_num_devs(file_path),
    }
