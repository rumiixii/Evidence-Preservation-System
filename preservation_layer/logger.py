"""
preservation_layer/logger.py

CompletionLogger class - writes the audit trail entry
after a preservation session completes.

The completion log records:
- Timestamp of the triggering event
- Timestamp of preservation completion
- Storage path of the stego-image (added by layer 3)
- SHA-256 hash of the encrypted archive
- Session ID
- Time elapsed

This log is the audit trail that confirms the preservation
cycle completed successfully and is referenced in chapter 5
evaluation.
"""

import logging
import os
from datetime import datetime

logger = logging.getLogger("eps.preservation.logger")


class CompletionLogger:
    """
    Writes structured audit trail entries to the completion log.

    Parameters
    ----------
    log_dir : str
        Directory where the completion log is written.
        Defaults to logs/ in the project root.
    """

    LOG_FILENAME = "preservation_completion.log"

    def __init__(self, log_dir: str):
        self.log_dir  = log_dir
        self.log_path = os.path.join(log_dir, self.LOG_FILENAME)
        os.makedirs(log_dir, exist_ok=True)

    def write(
        self,
        session_id: str,
        trigger_time: str,
        completion_time: str,
        elapsed_s: float,
        enc_path: str,
        hash_hex: str,
        hash_path: str,
        key_path: str,
        stego_path: str = "PENDING - layer 3 not yet executed",
        decoy_path: str = "PENDING - layer 3 not yet executed",
        success: bool = True,
        error: str = None,
    ) -> None:
        """
        Append a structured entry to the completion log.

        Parameters
        ----------
        session_id      : unique session identifier e.g. 20260601_135023
        trigger_time    : human-readable time the trigger fired
        completion_time : human-readable time the session completed
        elapsed_s       : total seconds taken for preservation cycle
        enc_path        : path to the encrypted archive
        hash_hex        : SHA-256 hash of the encrypted archive
        hash_path       : path to the .hash file
        key_path        : path to the .key file
        stego_path      : path to the stego-image (filled by layer 3)
        decoy_path      : path to the decoy store (filled by layer 3)
        success         : whether the session completed successfully
        error           : error message if success is False
        """

        status = "SUCCESS" if success else "FAILED"

        entry = f"""
================================================================================
PRESERVATION SESSION: {session_id}
Status             : {status}
================================================================================
TIMING
  Trigger fired    : {trigger_time}
  Completed        : {completion_time}
  Elapsed          : {elapsed_s:.2f} seconds

EVIDENCE
  Encrypted archive: {enc_path}
  SHA-256 hash     : {hash_hex}
  Hash file        : {hash_path}
  Key file         : {key_path}

DECEPTION LAYER
  Stego-image      : {stego_path}
  Decoy store      : {decoy_path}
"""

        if not success and error:
            entry += f"\nERROR\n  {error}\n"

        entry += "================================================================================\n"

        try:
            with open(self.log_path, "a") as f:
                f.write(entry)
            logger.info("Completion log written → %s", self.log_path)
        except Exception as e:
            logger.error("Failed to write completion log: %s", e)

    def read_all(self) -> str:
        """Read and return the full completion log contents."""
        if not os.path.exists(self.log_path):
            return "No completion log found."
        with open(self.log_path, "r") as f:
            return f.read()

    def get_last_session(self) -> str:
        """Return just the last session entry from the log."""
        if not os.path.exists(self.log_path):
            return "No completion log found."

        with open(self.log_path, "r") as f:
            content = f.read()

        sessions = content.split(
            "================================================================================"
        )
        # Get last non-empty block
        for block in reversed(sessions):
            if block.strip():
                return block.strip()
        return "No sessions found."