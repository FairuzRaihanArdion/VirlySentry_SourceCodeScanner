import fnmatch
import os
from typing import Iterator, List

from virlysentry.config.loader import ScanSettings


def _matches_any(name: str, patterns: List[str]) -> bool:
    return any(fnmatch.fnmatch(name, p) for p in patterns)


def walk_source_files(
    root_path: str,
    settings: ScanSettings,
    include_globs: List[str] = None,
    exclude_globs: List[str] = None,
) -> Iterator[str]:
    include_globs = include_globs or []
    exclude_globs = exclude_globs or []
    max_bytes = settings.max_file_size_kb * 1024

    if os.path.isfile(root_path):
        yield root_path
        return

    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if d not in settings.excluded_dirs and not d.startswith(".git")]

        for filename in filenames:
            full_path = os.path.join(dirpath, filename)
            rel_path = os.path.relpath(full_path, root_path)
            ext = os.path.splitext(filename)[1].lower()

            if ext in settings.binary_extensions:
                continue
            if exclude_globs and _matches_any(rel_path, exclude_globs):
                continue
            if include_globs and not _matches_any(rel_path, include_globs):
                continue
            try:
                if os.path.getsize(full_path) > max_bytes:
                    continue
            except OSError:
                continue

            yield full_path
