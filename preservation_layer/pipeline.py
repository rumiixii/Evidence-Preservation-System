"""
preservation_layer/pipeline.py

The main entry point for layer 2.
Called by the detection layer trigger.

Coordinates:
1. PreservationEngine  - capture and encrypt
2. CompletionLogger    - audit trail
3. Hands result to layer 3 (deception layer)
"""

import logging
import os
import sys
import time
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from config import EVIDENCE_DIR, LOG_DIR, RESPONSE_WINDOW_S
from preservation_layer.capture import PreservationEngine
from preservation_layer.logger import CompletionLogger

logger = logging.getLogger("eps.preservation.pipeline")


def run_preservation_pipeline(event, trigger_timestamp: float) -> dict:
    """
    Execute the full layer 2 preservation pipeline.

    Called by the detection layer daemon when a trigger fires.

    Parameters
    ----------
    event           : watchdog FileSystemEvent
    trigger_timestamp : float from time.monotonic()

    Returns the result dict from PreservationEngine.run()
    with stego_path and decoy_path added by layer 3.
    """
    trigger_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    logger.warning("PRESERVATION PIPELINE TRIGGERED")
    logger.warning("  Event : %s", type(event).__name__)
    logger.warning("  Path  : %s", event.src_path)
    logger.warning("  Time  : %s", trigger_time)

    # ── Run preservation engine ──────────────────────────────────────
    engine = PreservationEngine(
        evidence_dir=EVIDENCE_DIR,
        response_window_s=RESPONSE_WINDOW_S,
    )
    result = engine.run(trigger_timestamp)

    completion_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Write completion log ─────────────────────────────────────────
    completion_logger = CompletionLogger(log_dir=LOG_DIR)
    completion_logger.write(
        session_id      = result["session_id"],
        trigger_time    = trigger_time,
        completion_time = completion_time,
        elapsed_s       = result["elapsed_s"] or 0.0,
        enc_path        = result["enc_path"]  or "N/A",
        hash_hex        = result["hash_hex"]  or "N/A",
        hash_path       = result["hash_path"] or "N/A",
        key_path        = result["key_path"]  or "N/A",
        success         = result["success"],
        error           = result["error"],
    )

    if result["success"]:
        logger.info("Layer 2 complete — handing to layer 3")
        from deception_layer.pipeline import run_deception_pipeline
        deception_result = run_deception_pipeline(result)
        result["stego_path"] = deception_result.get("stego_path")
        result["decoy_path"] = deception_result.get("decoy_path")
        
    else:
        logger.error("Preservation failed — layer 3 not triggered")

    return result