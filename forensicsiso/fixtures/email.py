"""Build email fixtures: .eml and .mbox."""
from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders


def build_eml_fixture(dest: str) -> str:
    """Build a realistic .eml file with headers, body, and attachment."""
    msg = MIMEMultipart()
    msg["From"] = "alice@example.com"
    msg["To"] = "bob@example.com, charlie@example.com"
    msg["Cc"] = "dave@example.com"
    msg["Subject"] = "Project Update - Q3 Report"
    msg["Date"] = "Mon, 09 Sep 2026 10:30:00 +0000"
    msg["Message-ID"] = "<20260909103000.abc123@example.com>"
    msg["X-Mailer"] = "Python email module"
    msg["Received"] = "from mail.example.com (mail.example.com [10.0.0.1]) by mx.example.org"

    body = """Hi Bob and Charlie,

Please find the Q3 report attached. The key findings are:

1. Revenue increased 15% over Q2
2. Alice from alice@example.com will present at the board meeting
3. Security audit passed with zero critical findings

Best regards,
Alice
"""
    msg.attach(MIMEText(body, "plain"))

    attachment = MIMEBase("application", "octet-stream")
    attachment.set_payload(b"FAKE_PDF_CONTENT_Q3_REPORT_BINARY_DATA_HERE")
    encoders.encode_base64(attachment)
    attachment.add_header("Content-Disposition", "attachment", filename="Q3_Report.pdf")
    msg.attach(attachment)

    with open(dest, "w") as f:
        f.write(msg.as_string())
    return dest


def build_mbox_fixture(dest: str) -> str:
    """Build a mbox file with 3 messages."""
    messages = [
        {
            "From": "alice@example.com",
            "To": "bob@example.com",
            "Subject": "Meeting Tomorrow",
            "Date": "Mon, 09 Sep 2026 09:00:00 +0000",
            "Message-ID": "<msg001@example.com>",
            "Body": "Hi Bob, can we meet at 10am tomorrow? Alice from alice@example.com.\n",
        },
        {
            "From": "charlie@example.com",
            "To": "alice@example.com",
            "Subject": "Re: Meeting Tomorrow",
            "Date": "Mon, 09 Sep 2026 09:30:00 +0000",
            "Message-ID": "<msg002@example.com>",
            "Body": "Sure, 10am works. See you then. Charlie\n",
        },
        {
            "From": "alice@example.com",
            "To": "bob@example.com",
            "Subject": "Lunch Plans",
            "Date": "Mon, 09 Sep 2026 12:00:00 +0000",
            "Message-ID": "<msg003@example.com>",
            "Body": "Want to grab lunch? alice@example.com\n",
        },
    ]
    with open(dest, "w") as f:
        for msg in messages:
            f.write(f"From {msg['From']} {msg['Date']}\n")
            for key in ["From", "To", "Subject", "Date", "Message-ID"]:
                f.write(f"{key}: {msg[key]}\n")
            f.write(f"\n{msg['Body']}\n\n")
    return dest
