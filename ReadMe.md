
# Beyond Detection: An Anti-Forensic Evidence Preservation System Using Steganography and Deception

## Overview

This project implements a three-layer forensic evidence preservation system designed to protect digital evidence during an active anti-forensic attack. Existing defensive frameworks prioritize detection and prevention but leave forensic evidence vulnerable to destruction before investigators can access it. This system addresses that gap by capturing, encrypting, and concealing forensic artifacts at the moment they are most at risk — during the attack itself.

The system targets MITRE ATT&CK T1070 indicator removal techniques, specifically T1070.002 (Clear Linux or Mac System Logs) and T1070.004 (File Deletion) on Ubuntu Linux.


## System Architecture


Attacker (Kali Linux VM) → SSH intrusion → deletes /var/log
                                    ↓
              Layer 1: Detection Layer
              inotify daemon watches /var/log and key paths
              Fires trigger + sends email alert to security personnel
                                    ↓
              Layer 2: Preservation Layer
              Captures artifacts in order of volatility:
              processes → network connections → users → bash history → logs
              AES-256 encryption + SHA-256 integrity hashing
                                    ↓
              Layer 3: Deception Layer
              Deploys convincing decoy evidence store (obvious location)
              Conceals real evidence via LSB steganography in carrier image
              Writes completion log with all session details

---
## Project Structure


Evidence-Preservation-System/

├── detection_layer/
│   ├── daemon.py            # inotify detection daemon - main entry point
│   ├── event_handler.py     # event classification and trigger logic
│   └── alerting.py          # email alert to security personnel via Gmail SMTP
├── preservation_layer/
│   ├── capture.py           # artifact capture following order of volatility
│   ├── crypto.py            # AES-256 encryption and SHA-256 hashing
│   ├── logger.py            # completion log writer (CompletionLogger)
│   └── pipeline.py          # layer 2 coordinator
├── deception_layer/
│   ├── steganography.py     # LSB steganographic embedding and extraction
│   ├── decoy.py             # decoy evidence store generator
│   └── pipeline.py          # layer 3 coordinator (DeceptionLayer class)
├── tests/
│   ├── test_detection.py    # 5 unit tests for detection layer
│   ├── test_preservation.py # 11 unit tests for preservation layer
│   └── test_deception.py    # 11 unit tests for deception layer
├── evidence_store/          # encrypted real evidence (gitignored)
├── decoy_store/             # fake evidence store (gitignored)
├── carrier_images/          # steganographic carrier image (gitignored)
├── logs/                    # system and completion logs (gitignored)
├── config.py                # central configuration
└── .env                     # credentials (gitignored, never committed)


---

## Technologies Used

| Library | Version | Purpose |
|---------|---------|---------|
| Python | 3.12.3 | Core implementation language |
| watchdog | 6.0.0 | inotify-based file system monitoring |
| pycryptodome | 3.23.0 | AES-256 encryption (EAX mode) |
| stegano | 2.4.1 | LSB steganographic embedding and extraction |
| Pillow | 12.1.1 | Image processing and capacity verification |
| python-dotenv | 1.2.2 | Secure credential management |
| pytest | 9.1.1 | Automated unit testing |
| smtplib | Standard library | Email alerting via Gmail SMTP SSL |

---

## Setup

### Prerequisites
- Ubuntu 22.04 or 24.04 LTS
- Python 3.10+
- Virtual environment

### Installation

git clone https://github.com/rumiixii/Evidence-Preservation-System.git
cd Evidence-Preservation-System
python3 -m venv venv
source venv/bin/activate
pip install watchdog pycryptodome stegano pillow python-dotenv pytest


### Configuration

Create a `.env` file in the project root:


ALERT_SENDER=your.sender@gmail.com
ALERT_PASSWORD=your_app_password
ALERT_RECIPIENT=your.recipient@gmail.com

Place a PNG carrier image (minimum 4000x3000 recommended) in "carrier_images/".

---

## Running the System

**Activate virtual environment first**
source venv/bin/activate

**Run all unit tests (27 tests across all three layers)**
python3 -m pytest tests/ -v

**Run detection layer self-test**
python3 -m detection_layer.daemon --test

**Start the full daemon (all three layers active)**
python3 -m detection_layer.daemon --verbose

---

## Evaluation Results

| Metric | Target | Result |
|--------|--------|--------|
| SHA-256 hash match rate | 100% | 100% (all test runs) |
| Evidence capture success rate | ≥ 70% | 100% |
| Full preservation cycle time | ≤ 60 seconds | Mean: 0.81 seconds |
| Unit tests passing | All | 27/27 |

---

## Attack Simulation

The system was validated against a scripted SSH intrusion from a Kali Linux 2026 VM targeting MITRE T1070.002 and T1070.004. The attacker connected via SSH and executed targeted deletion of "/var/log/syslog", "/var/log/auth.log", and "/var/log/kern.log". The preservation system detected the deletions, captured and encrypted the evidence, concealed it in a stego-image, deployed a decoy, and dispatched an email alert, all within 0.87 seconds.

---

## Evidence Recovery

To verify evidence integrity after preservation:

python3 -c "
import sys, os, hashlib
sys.path.insert(0, '.')
from deception_layer.steganography import extract_evidence

session_id = 'YOUR_SESSION_ID'
stego_path = os.path.expanduser('~/.cache/thumbnails/large/') + session_id + '.png'
hash_path  = 'evidence_store/session_' + session_id + '.hash'
extracted  = '/tmp/recovered_' + session_id + '.enc'

extract_evidence(stego_path, extracted)

with open(hash_path) as f:
    original_hash = f.read().split()[0]

sha256 = hashlib.sha256()
with open(extracted, 'rb') as f:
    for chunk in iter(lambda: f.read(8192), b''):
        sha256.update(chunk)

print('HASH MATCH' if original_hash == sha256.hexdigest() else 'MISMATCH')
"

---

## Layer Status

| Layer | Status | Tests |
|-------|--------|-------|
| Detection | Complete | 5/5 passing |
| Preservation | Complete | 11/11 passing |
| Deception | Complete | 11/11 passing |
| Integration | Complete | Live attack simulation validated |

---

## Research Context

Developed as a Bachelor of Science final year project at Strathmore University. Evaluated using Design Science Research methodology with an explanatory sequential mixed methods design. The project contributes a novel integration of inotify-based detection, AES-256 cryptographic preservation, and LSB steganographic concealment into a coordinated real-time evidence preservation architecture.

