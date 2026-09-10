"""Email parser — .eml (MIME) and mbox fixture parsing."""
from __future__ import annotations

import mailbox
import os
import re
from email import message_from_file
from email.mime.multipart import MIMEMultipart
from typing import Any, Dict, List, Optional

from forensicsiso.hashing import sha256_file, sha256_bytes
from forensicsiso.custody import CustodyManifest

EMAIL_RE = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')


def parse_eml(path: str, custody: Optional[CustodyManifest] = None) -> Dict[str, Any]:
    """Parse a single .eml file."""
    if custody:
        custody.add_file(path, "eml_file")

    with open(path) as f:
        msg = message_from_file(f)

    headers = {
        "From": msg.get("From", ""),
        "To": msg.get("To", ""),
        "Cc": msg.get("Cc", ""),
        "Subject": msg.get("Subject", ""),
        "Date": msg.get("Date", ""),
        "Message-ID": msg.get("Message-ID", ""),
        "X-Mailer": msg.get("X-Mailer", ""),
        "Received": msg.get("Received", ""),
    }

    body = ""
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            fn = part.get_filename()
            if fn:
                payload = part.get_payload(decode=True) or b""
                attachments.append({
                    "filename": fn,
                    "content_type": ct,
                    "size": len(payload),
                    "sha256": sha256_bytes(payload),
                })
            elif ct == "text/plain" and body == "":
                body = part.get_payload(decode=True).decode(errors="replace")
    else:
        body = msg.get_payload(decode=True)
        if body:
            body = body.decode(errors="replace")

    emails_found = set()
    for val in headers.values():
        if val:
            emails_found.update(EMAIL_RE.findall(val))
    if body:
        emails_found.update(EMAIL_RE.findall(body))

    result = {
        "type": "eml",
        "path": os.path.abspath(path),
        "sha256": sha256_file(path),
        "headers": headers,
        "body_preview": body[:500] if body else "",
        "attachments": attachments,
        "emails_found": sorted(emails_found),
    }
    if custody:
        result["custody_hash"] = custody.add_json_output("eml_analysis", result)
    return result


def parse_mbox(path: str, custody: Optional[CustodyManifest] = None) -> Dict[str, Any]:
    """Parse an mbox file containing multiple messages."""
    if custody:
        custody.add_file(path, "mbox_file")

    mbox = mailbox.mbox(path)
    messages = []
    all_emails = set()

    for i, msg in enumerate(mbox, 1):
        headers = {
            "From": msg.get("From", ""),
            "To": msg.get("To", ""),
            "Subject": msg.get("Subject", ""),
            "Date": msg.get("Date", ""),
            "Message-ID": msg.get("Message-ID", ""),
        }
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    body = part.get_payload(decode=True).decode(errors="replace")
                    break
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                body = payload.decode(errors="replace")

        emails_in_msg = set()
        for val in headers.values():
            if val:
                emails_in_msg.update(EMAIL_RE.findall(val))
        if body:
            emails_in_msg.update(EMAIL_RE.findall(body))
        all_emails.update(emails_in_msg)

        messages.append({
            "index": i,
            "headers": headers,
            "body_preview": body[:300] if body else "",
            "emails_in_message": sorted(emails_in_msg),
        })

    mbox.close()

    result = {
        "type": "mbox",
        "path": os.path.abspath(path),
        "sha256": sha256_file(path),
        "message_count": len(messages),
        "messages": messages,
        "emails_found": sorted(all_emails),
    }
    if custody:
        result["custody_hash"] = custody.add_json_output("mbox_analysis", result)
    return result
