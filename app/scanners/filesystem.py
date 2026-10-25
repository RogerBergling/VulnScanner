"""Filesystem traversal guards shared by repo scanners."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator

from ..config import MAX_SCAN_FILES, MAX_SOURCE_FILE_BYTES

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "bower_components", ".venv", "venv",
    "env", "__pycache__", ".pytest_cache", ".mypy_cache", ".tox", "dist", "build",
    "target", "coverage", ".next", ".nuxt", ".cache", ".idea", ".terraform",
    "vendor", "Pods", "DerivedData", ".gradle", ".m2", "site-packages",
    "windows", "winsxs", "System32",
}
BINARY_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz",
    ".bz2", ".xz", ".7z", ".rar", ".tar", ".jar", ".war", ".ear", ".class",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".dat", ".db", ".sqlite", ".woff",
    ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".mov", ".avi", ".iso", ".img",
    ".pyc", ".pyo", ".o", ".a", ".obj", ".pdb", ".lockb",
}


def safe_file(path: Path, max_size: int = MAX_SOURCE_FILE_BYTES) -> bool:
    try:
        if path.is_symlink() or not path.is_file():
            return False
        if path.stat().st_size > max_size:
            return False
        if path.suffix.lower() in BINARY_SUFFIXES:
            return False
        return True
    except OSError:
        return False


def iter_files(
    root: str | Path,
    max_files: int = MAX_SCAN_FILES,
    max_size: int = MAX_SOURCE_FILE_BYTES,
    extra_skip_dirs: set[str] | None = None,
) -> Iterator[Path]:
    root = Path(root).resolve()
    skip = SKIP_DIRS | (extra_skip_dirs or set())
    count = 0
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [
            name for name in dirs
            if name not in skip and not (Path(current) / name).is_symlink()
        ]
        for name in files:
            path = Path(current) / name
            if not safe_file(path, max_size):
                continue
            yield path
            count += 1
            if count >= max_files:
                return


def read_text_file(path: Path, limit: int = MAX_SOURCE_FILE_BYTES) -> str:
    data = path.read_bytes()[:limit]
    if b"\x00" in data[:4096]:
        return ""
    for encoding in ("utf-8", "utf-16", "latin-1"):
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, UnicodeError):
            continue
    return ""


def relative_path(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve())).replace(os.sep, "/")
    except ValueError:
        return str(path)
