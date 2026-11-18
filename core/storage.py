"""Atomic, private JSON persistence with stat-based read caching."""
import json
import os
import tempfile
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=16)
def _read(path, mtime, size):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def read_json(path):
    stat = path.stat()
    return _read(str(path), stat.st_mtime_ns, stat.st_size)


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    name = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as file:
            name = file.name
            json.dump(value, file, indent=2)
            file.flush()
            os.fsync(file.fileno())
        os.replace(name, path)
        _read.cache_clear()
    finally:
        if name and os.path.exists(name):
            os.unlink(name)
