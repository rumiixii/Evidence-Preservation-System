"""
preservation_layer/capture.py

PreservationEngine class - captures forensic artifacts in order
of volatility and produces an encrypted archive.

Order of volatility (most to least transient):
1. Running processes
2. Network connections
3. Logged in users
4. Bash history
5. Log files from /var/log
"""

import logging
import os
import shutil
import subprocess
import tarfile
import tempfile
from datetime import datetime

logger = logging.getLogger("eps.preservation.capture")


class PreservationEngine:
    """
    Captures system artifacts in order of volatility,
    compresses them, encrypts the archive, and computes
    a SHA-256 integrity hash.

    Parameters
    ----------
    evidence_dir : str
        Path to evidence_store/ where encrypted output is saved.
    response_window_s : float
        Maximum seconds allowed for the full capture cycle.
    """

    def __init__(self, evidence_dir: str, response_window_s: float = 30.0):
        self.evidence_dir       = evidence_dir
        self.response_window_s  = response_window_s
        os.makedirs(evidence_dir, exist_ok=True)

    def run(self, trigger_timestamp: float) -> dict:
        """
        Execute the full preservation pipeline.

        Parameters
        ----------
        trigger_timestamp : float
            time.monotonic() value from the detection trigger.

        Returns a result dict:
        {
            "success"       : bool,
            "session_id"    : str,
            "enc_path"      : str,
            "hash_hex"      : str,
            "hash_path"     : str,
            "key_path"      : str,
            "elapsed_s"     : float,
            "error"         : str or None,
        }
        """
        import time
        from preservation_layer.crypto import (
            generate_key, encrypt_archive, compute_hash
        )

        start_time = time.monotonic()
        session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        result = {
            "success"    : False,
            "session_id" : session_id,
            "enc_path"   : None,
            "hash_hex"   : None,
            "hash_path"  : None,
            "key_path"   : None,
            "elapsed_s"  : None,
            "error"      : None,
        }

        # Temporary staging directory - deleted after encryption
        staging_dir = tempfile.mkdtemp(prefix=f"eps_staging_{session_id}_")
        archive_path = None

        try:
            logger.info("=" * 55)
            logger.info("PRESERVATION SESSION %s STARTED", session_id)
            logger.info("=" * 55)

            # ── Step 1: Capture volatile artifacts ──────────────────
            self._capture_processes(staging_dir)
            self._capture_network(staging_dir)
            self._capture_users(staging_dir)

            # ── Step 2: Capture semi-volatile artifacts ──────────────
            self._capture_bash_history(staging_dir)
            self._capture_logs(staging_dir)

            # ── Step 3: Check timing before encryption ───────────────
            elapsed = time.monotonic() - start_time
            logger.info("Artifact capture complete in %.2fs", elapsed)

            if elapsed > self.response_window_s * 0.7:
                logger.warning(
                    "Capture used %.0f%% of response window — encryption may be tight",
                    (elapsed / self.response_window_s) * 100
                )

            # ── Step 4: Compress staging directory ───────────────────
            archive_path = os.path.join(
                self.evidence_dir, f"session_{session_id}.tar.gz"
            )
            with tarfile.open(archive_path, "w:gz") as tar:
                tar.add(staging_dir, arcname=f"session_{session_id}")
            logger.info("Staging compressed → %s", archive_path)

            # ── Step 5: Generate key and encrypt ─────────────────────
            key, key_path = generate_key(self.evidence_dir, session_id)
            enc_path      = encrypt_archive(archive_path, key, self.evidence_dir, session_id)

            # ── Step 6: SHA-256 hash the encrypted archive ────────────
            hash_hex, hash_path = compute_hash(enc_path, self.evidence_dir, session_id)

            # ── Step 7: Delete unencrypted archive ───────────────────
            os.remove(archive_path)
            archive_path = None
            logger.info("Unencrypted archive deleted")

            elapsed_total = time.monotonic() - start_time
            result.update({
                "success"   : True,
                "enc_path"  : enc_path,
                "hash_hex"  : hash_hex,
                "hash_path" : hash_path,
                "key_path"  : key_path,
                "elapsed_s" : elapsed_total,
            })

            logger.info("PRESERVATION COMPLETE in %.2fs", elapsed_total)
            if elapsed_total > self.response_window_s:
                logger.warning(
                    "Response window exceeded: %.2fs > %.2fs",
                    elapsed_total, self.response_window_s
                )

        except Exception as e:
            result["error"] = str(e)
            logger.error("Preservation failed: %s", e, exc_info=True)

        finally:
            # Always clean up staging directory
            if os.path.exists(staging_dir):
                shutil.rmtree(staging_dir)
                logger.info("Staging directory cleaned up")
            # Clean up unencrypted archive if encryption failed
            if archive_path and os.path.exists(archive_path):
                os.remove(archive_path)

        return result

    # ── Artifact capture methods ─────────────────────────────────────────

    def _capture_processes(self, staging_dir: str) -> None:
        """Capture running processes - most volatile artifact."""
        output_path = os.path.join(staging_dir, "processes.txt")
        try:
            result = subprocess.run(
                ["ps", "aux"],
                capture_output=True, text=True, timeout=10
            )
            with open(output_path, "w") as f:
                f.write(f"PROCESS SNAPSHOT\nCaptured: {datetime.now()}\n")
                f.write("=" * 60 + "\n")
                f.write(result.stdout)
            logger.info("Processes captured (%d bytes)", os.path.getsize(output_path))
        except Exception as e:
            logger.error("Failed to capture processes: %s", e)
            with open(output_path, "w") as f:
                f.write(f"CAPTURE FAILED: {e}\n")

    def _capture_network(self, staging_dir: str) -> None:
        """Capture network connections."""
        output_path = os.path.join(staging_dir, "network.txt")
        try:
            result = subprocess.run(
                ["ss", "-tulnp"],
                capture_output=True, text=True, timeout=10
            )
            with open(output_path, "w") as f:
                f.write(f"NETWORK CONNECTIONS\nCaptured: {datetime.now()}\n")
                f.write("=" * 60 + "\n")
                f.write(result.stdout)
            logger.info("Network connections captured")
        except Exception as e:
            logger.error("Failed to capture network: %s", e)
            with open(output_path, "w") as f:
                f.write(f"CAPTURE FAILED: {e}\n")

    def _capture_users(self, staging_dir: str) -> None:
        """Capture logged in users."""
        output_path = os.path.join(staging_dir, "users.txt")
        try:
            result = subprocess.run(
                ["who"],
                capture_output=True, text=True, timeout=10
            )
            with open(output_path, "w") as f:
                f.write(f"LOGGED IN USERS\nCaptured: {datetime.now()}\n")
                f.write("=" * 60 + "\n")
                f.write(result.stdout)
            logger.info("Users captured")
        except Exception as e:
            logger.error("Failed to capture users: %s", e)
            with open(output_path, "w") as f:
                f.write(f"CAPTURE FAILED: {e}\n")

    def _capture_bash_history(self, staging_dir: str) -> None:
        """Capture bash history."""
        output_path = os.path.join(staging_dir, "bash_history.txt")
        history_path = os.path.expanduser("~/.bash_history")
        try:
            if os.path.exists(history_path):
                shutil.copy2(history_path, output_path)
                logger.info("Bash history captured")
            else:
                with open(output_path, "w") as f:
                    f.write("Bash history file not found\n")
        except Exception as e:
            logger.error("Failed to capture bash history: %s", e)
            with open(output_path, "w") as f:
                f.write(f"CAPTURE FAILED: {e}\n")
    def _capture_logs(self, staging_dir: str) -> None:
        """Copy /var/log contents to staging."""
        log_staging = os.path.join(staging_dir, "var_log")
        os.makedirs(log_staging, exist_ok=True)
        log_dir = "/var/log"
        captured = 0
        failed = 0

        try:
            for filename in os.listdir(log_dir):
                src = os.path.join(log_dir, filename)
                dst = os.path.join(log_staging, filename)
                try:
                    if os.path.isfile(src):
                        shutil.copy2(src, dst)
                        captured += 1
                except PermissionError:
                    failed += 1
                except Exception as e:
                    logger.debug("Could not copy %s: %s", filename, e)
                    failed += 1

            logger.info(
                "Log files captured: %d succeeded, %d skipped (permission)",
                captured, failed
            )
        except Exception as e:
            logger.error("Failed to capture logs: %s", e)
    