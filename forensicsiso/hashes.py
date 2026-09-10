"""Evidence integrity — hash verification, chain-of-custody."""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from forensicsiso.hashing import sha256_file, sha256_str
from forensicsiso.custody import CustodyManifest


def verify_artifact_hashes(artifacts: List[str], expected: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Verify hashes of evidence files against expected values."""
    results = []
    for path in artifacts:
        actual = sha256_file(path)
        exp = expected.get(path) if expected else None
        match = exp == actual if exp else None
        results.append({
            "path": os.path.abspath(path),
            "sha256": actual,
            "expected": exp,
            "match": match,
            "verified": match is True if exp else "no_expected",
        })
    all_ok = all(r["verified"] is True for r in results if r["expected"])
    return {"results": results, "all_verified": all_ok}


def build_custody_report(manifest_path: str) -> Dict[str, Any]:
    """Build a custody report from a manifest file."""
    ok = CustodyManifest.verify(manifest_path)
    with open(manifest_path) as f:
        data = json.load(f)
    return {
        "manifest_path": os.path.abspath(manifest_path),
        "manifest_valid": ok,
        "entry_count": data.get("entry_count", 0),
        "manifest_hash": data.get("manifest_hash", ""),
    }
