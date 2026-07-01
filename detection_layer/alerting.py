"""
detection_layer/alerting.py

Sends an email alert to security personnel when a
suspicious event is detected.
"""

import logging
import os
import smtplib
import ssl
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

logger = logging.getLogger("eps.alerting")


def _get_credentials():
    """Load credentials from .env file."""
    try:
        from dotenv import load_dotenv
        # Explicitly point to project root .env
        env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
        load_dotenv(dotenv_path=os.path.abspath(env_path))
    except ImportError:
        pass
    return (
        os.getenv("ALERT_SENDER"),
        os.getenv("ALERT_PASSWORD"),
        os.getenv("ALERT_RECIPIENT"),
    )


def send_alert(event_type: str, event_path: str) -> bool:
    """
    Send an email alert when a suspicious event is detected.
    """
    sender, password, recipient = _get_credentials()

    if not all([sender, password, recipient]):
        logger.error("Email credentials missing — check .env file")
        return False

    event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    subject    = f"[EPS ALERT] Suspicious Activity Detected — {event_time}"

    body = f"""
EVIDENCE PRESERVATION SYSTEM — SECURITY ALERT
{'=' * 50}

A suspicious file system event has been detected.
The preservation pipeline has been triggered.

DETAILS
-------
Time        : {event_time}
Event Type  : {event_type}
Affected    : {event_path}

WHAT THIS MEANS
---------------
An attacker may be attempting to delete or tamper
with forensic evidence on this system.

The preservation layer has automatically:
  1. Captured a snapshot of volatile evidence
  2. Encrypted and hashed the captured artifacts
  3. Concealed the real evidence using steganography
  4. Deployed a decoy evidence store

ACTION REQUIRED
---------------
Investigate the affected path immediately:
  {event_path}

-- Evidence Preservation System
"""

    try:
        msg            = MIMEMultipart()
        msg["From"]    = sender
        msg["To"]      = recipient
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(sender, password)
            server.sendmail(sender, recipient, msg.as_string())

        logger.info("Alert email sent to %s", recipient)
        print(f"Alert email sent to {recipient}")
        return True

    except smtplib.SMTPAuthenticationError:
        logger.error("Gmail authentication failed — check app password in .env")
        print("ERROR: Gmail authentication failed")
        return False
    except Exception as e:
        logger.error("Failed to send alert: %s", e)
        print(f"ERROR sending email: {e}")
        return False


if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    print("Sending test alert...")
    result = send_alert(
        event_type="FileDeletedEvent",
        event_path="/var/log/syslog"
    )
    print("SUCCESS" if result else "FAILED")