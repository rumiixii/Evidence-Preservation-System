import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Detection layer - paths to watch
WATCHED_PATHS = [
    "/var/log",
    os.path.expanduser("~/.bash_history"),
    "/tmp",
]

IGNORE_PATTERNS = [
    "*.swp", "*.tmp", "*.lock",
    "/var/log/journal",
    "/var/log/wtmp",
    "/var/log/btmp",
    "/var/log/lastlog",
]

# Preservation layer
EVIDENCE_DIR      = os.path.join(BASE_DIR, "evidence_store")
RESPONSE_WINDOW_S = 60

# Deception layer
DECOY_DIR         = os.path.join(BASE_DIR, "decoy_store")
CARRIER_IMAGE_DIR = os.path.join(BASE_DIR, "carrier_images")

# Logging
LOG_DIR  = os.path.join(BASE_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "eps.log")