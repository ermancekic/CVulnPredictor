"""
project_metrics.py

Git-based project/file history metrics.

Implements project/file history metrics per file (tracked with git --follow):
- NumChanges:  number of commits that touched the file since creation
- LinesChanged: cumulative added + deleted lines across all touching commits
- LinesNew:  cumulative added lines across all touching commits
- NumDevs: number of distinct authors (by email) who touched the file
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
def _rel_to_root(repo_root: str, file_path: str) -> str:
    try:
        return os.path.relpath(os.path.abspath(file_path), repo_root)
    except Exception:
        return file_path


@lru_cache(maxsize=131072)
def _history_rollup(repo_root: str, rel_path: str) -> Tuple[int, int, int, int]:
    """Return (num_commits, total_added, total_deleted, num_authors) for file history.

    Ein einziger `git log`-Durchlauf mit:
    - `--follow` (Rename-Erkennung)
    - `--no-merges` (Merges nicht doppelt zählen)
    - `--numstat` (Added/Deleted je Commit)
    - `--format=%x00%H%x00%ae%x00` (Commit-Marker mit NUL-Delimiter für robustes Parsen)
    """
    out = _git_run(
        repo_root,
        [
            "log",
            "--follow",
            "--no-merges",
            "--numstat",
            "--format=%x00%H%x00%ae%x00",
            "--",
            rel_path,
        ],
    )

    num_commits = 0
    total_added = 0
    total_deleted = 0
    authors = set()

    for line in out.splitlines():
        if not line:
            continue

        # Commit-Marker: \x00<hash>\x00<email>\x00
        if line.startswith("\x00"):
            num_commits += 1
            marker = line[1:]  # führendes NUL entfernen
            fields = marker.split("\x00")
            # Erwartet: ["<hash>", "<email>", ""] oder mindestens hash+email
            if len(fields) >= 2:
                email = (fields[1] or "").strip().lower()
                if email:
                    authors.add(email)
            continue

        # Numstat-Zeile: "<added>\t<deleted>\t<path>"
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        a, d = parts[0].strip(), parts[1].strip()
        if a.isdigit():
            total_added += int(a)
        # Bei Binärdiffs steht '-' – nur numerische Werte verwenden
        if d.isdigit():
            total_deleted += int(d)

    return num_commits, total_added, total_deleted, len(authors)


def calculate_num_changes(file_path: str) -> int:
    """Number of commits that touched the file since its creation (git --follow)."""
    root = _find_git_root(file_path)
    if not root:
        return 0
    rel = _rel_to_root(root, file_path)
    n, _a, _d, _devs = _history_rollup(root, rel)
    return n


def calculate_lines_changed(file_path: str) -> int:
    """Cumulated number of code lines changed (added + deleted) since creation."""
    root = _find_git_root(file_path)
    if not root:
        return 0
    rel = _rel_to_root(root, file_path)
    _n, a, d, _devs = _history_rollup(root, rel)
    return a + d


def calculate_lines_new(file_path: str) -> int:
    """Cumulated number of new code lines (added) since creation."""
    root = _find_git_root(file_path)
    if not root:
        return 0
    rel = _rel_to_root(root, file_path)
    _n, a, _d, _devs = _history_rollup(root, rel)
    return a


def calculate_num_devs(file_path: str) -> int:
    """Number of distinct authors (unique emails) who changed the file."""
    root = _find_git_root(file_path)
    if not root:
        return 0
    rel = _rel_to_root(root, file_path)
    _n, _a, _d, devs = _history_rollup(root, rel)
    return devs


def calculate_file_project_metrics(file_path: str) -> dict:
    """Convenience helper returning all metrics for a file path."""
    root = _find_git_root(file_path)
    if not root:
        return {
            "NumChanges": 0,
            "LinesChanged": 0,
            "LinesNew": 0,
            "NumDevs": 0,
        }
    rel = _rel_to_root(root, file_path)
    n, a, d, devs = _history_rollup(root, rel)
    return {
        "NumChanges": n,
        "LinesChanged": a + d,
        "LinesNew": a,
        "NumDevs": devs,
    }
