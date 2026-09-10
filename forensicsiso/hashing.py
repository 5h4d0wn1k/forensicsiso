"""SHA-256 hashing and evidence-integrity utilities."""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Union

BUF = 1 << 16


def sha256_file(path: Union[str, Path]) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(BUF)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_str(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def hash_json(obj: object) -> str:
    canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256_str(canonical)
