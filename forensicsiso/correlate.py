"""Cross-artifact correlation — person-hashing, suspicious-behavior signatures."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from forensicsiso.hashing import sha256_str, hash_json
from forensicsiso.custody import CustodyManifest

EMAIL_RE = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')


def _extract_emails(data: Any) -> Set[str]:
    """Recursively extract email addresses from nested data."""
    emails = set()
    if isinstance(data, str):
        emails.update(EMAIL_RE.findall(data))
    elif isinstance(data, dict):
        for v in data.values():
            emails.update(_extract_emails(v))
    elif isinstance(data, list):
        for item in data:
            emails.update(_extract_emails(item))
    return emails


def correlate_user_across_sources(*analyses: Dict[str, Any],
                                   custody: Optional[CustodyManifest] = None) -> Dict[str, Any]:
    """Find users appearing in multiple source types."""
    source_emails: Dict[str, Set[str]] = {}
    for analysis in analyses:
        src = analysis.get("type", "unknown")
        emails = _extract_emails(analysis)
        if emails:
            source_emails[src] = emails

    all_emails = set()
    for emails in source_emails.values():
        all_emails.update(emails)

    persons = []
    for email in all_emails:
        sources = [src for src, emails in source_emails.items() if email in emails]
        person_hash = sha256_str(email)
        persons.append({
            "email": email,
            "person_hash": person_hash,
            "sources": sources,
            "source_count": len(sources),
            "cross_correlated": len(sources) >= 3,
        })

    persons.sort(key=lambda x: x["source_count"], reverse=True)

    result = {
        "unique_users": len(all_emails),
        "cross_correlated_count": sum(1 for p in persons if p["cross_correlated"]),
        "persons": persons,
        "source_coverage": {src: len(emails) for src, emails in source_emails.items()},
    }
    if custody:
        result["custody_hash"] = custody.add_json_output("correlation", result)
    return result


def detect_suspicious_behaviors(*analyses: Dict[str, Any],
                                 custody: Optional[CustodyManifest] = None) -> List[Dict[str, Any]]:
    """Flag suspicious behavioral signatures across artifacts."""
    signatures = []

    # Check for delete operations
    for analysis in analyses:
        for anomaly in analysis.get("anomalies", []):
            atype = anomaly.get("type", "")
            if "delete" in atype.lower():
                signatures.append({
                    "type": "file_deletion",
                    "severity": "high",
                    "detail": (anomaly.get("detail") or anomaly.get("filename") or
                               anomaly.get("request") or ""),
                    "source": analysis.get("type", "unknown"),
                })
            if "audit_log_cleared" in atype:
                signatures.append({
                    "type": "log_tampering",
                    "severity": "critical",
                    "detail": anomaly.get("message", ""),
                    "source": analysis.get("type", "unknown"),
                })
            if "account_created" in atype:
                signatures.append({
                    "type": "new_account",
                    "severity": "medium",
                    "detail": anomaly.get("message", ""),
                    "source": analysis.get("type", "unknown"),
                })
            if "group_member_added" in atype:
                signatures.append({
                    "type": "privilege_escalation",
                    "severity": "high",
                    "detail": anomaly.get("message", ""),
                    "source": analysis.get("type", "unknown"),
                })

    # Check for after-hours activity (before 6am or after 10pm)
    for analysis in analyses:
        for ev in analysis.get("events", []):
            ts = ev.get("timestamp", "")
            if not ts:
                continue
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                hour = dt.hour
                if 0 <= hour < 6 or 22 <= hour <= 23:
                    signatures.append({
                        "type": "after_hours_activity",
                        "severity": "low",
                        "timestamp": ts,
                        "detail": ev.get("message") or ev.get("request", ""),
                        "source": analysis.get("type", "unknown"),
                    })
            except (ValueError, TypeError):
                pass

    # USB/MBR write detection (from disk analysis)
    for analysis in analyses:
        if "recovered_deleted" in analysis:
            signatures.append({
                "type": "deleted_file_recovery",
                "severity": "high",
                "detail": f"recoverable deleted file at inode {analysis['recovered_deleted'].get('inode', '?')}",
                "source": "disk",
            })
        if "persistence" in analysis and analysis["persistence"]:
            for vk in analysis["persistence"]:
                signatures.append({
                    "type": "persistence_mechanism",
                    "severity": "high",
                    "detail": f"registry value: {vk.get('name', '?')} → {vk.get('decoded', '?')}",
                    "source": "registry",
                })

    # Failed login clustering
    for analysis in analyses:
        anomalies = analysis.get("anomalies", [])
        failed = [a for a in anomalies if "failed" in a.get("type", "").lower()]
        if len(failed) >= 3:
            signatures.append({
                "type": "brute_force",
                "severity": "high",
                "detail": f"{len(failed)} failed login attempts detected",
                "source": analysis.get("type", "unknown"),
            })

    return signatures
