"""Chain-of-custody manifest builder and verifier."""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from forensicsiso.hashing import sha256_file, sha256_bytes, hash_json


class CustodyManifest:
    """Accumulates evidence entries then serialises a JSON manifest."""

    def __init__(self) -> None:
        self.entries: List[Dict[str, Any]] = []
        self.started_at = datetime.now(timezone.utc).isoformat()

    def add_file(self, path: str, label: str = "") -> str:
        h = sha256_file(path)
        entry = {
            "type": "file",
            "path": os.path.abspath(path),
            "label": label or os.path.basename(path),
            "sha256": h,
            "size_bytes": os.path.getsize(path),
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }
        self.entries.append(entry)
        return h

    def add_output(self, name: str, data: bytes, label: str = "") -> str:
        h = sha256_bytes(data)
        entry = {
            "type": "output",
            "name": name,
            "label": label or name,
            "sha256": h,
            "size_bytes": len(data),
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }
        self.entries.append(entry)
        return h

    def add_json_output(self, name: str, obj: Any, label: str = "") -> str:
        raw = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        return self.add_output(name, raw, label)

    def manifest_hash(self) -> str:
        return hash_json(self.entries)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "forensicsiso_version": "1.0.0",
            "started_at": self.started_at,
            "entry_count": len(self.entries),
            "manifest_hash": self.manifest_hash(),
            "entries": self.entries,
        }

    def save(self, path: str) -> None:
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)

    @staticmethod
    def verify(path: str) -> bool:
        with open(path) as f:
            data = json.load(f)
        stored = data.get("manifest_hash", "")
        entries = data.get("entries", [])
        canonical = json.dumps(entries, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        computed = hash_json(entries)
        return stored == computed


def verify_manifest(path: str) -> bool:
    return CustodyManifest.verify(path)
