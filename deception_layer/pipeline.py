"""
deception_layer/pipeline.py

DeceptionLayer class - coordinates steganographic
concealment and decoy deployment.

Called by the preservation layer pipeline once the
encrypted archive is ready.
"""

import logging
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from config import DECOY_DIR, CARRIER_IMAGE_DIR, LOG_DIR
from deception_layer.steganography import embed_evidence
from deception_layer.decoy import DecoyGenerator
from preservation_layer.logger import CompletionLogger

logger = logging.getLogger("eps.deception.pipeline")


class DeceptionLayer:
    """
    Coordinates LSB steganographic concealment and
    decoy evidence store deployment.

    Parameters
    ----------
    carrier_image_dir : str
        Directory containing carrier images.
    decoy_dir         : str
        Directory where decoy store is deployed.
    """

    def __init__(self, carrier_image_dir: str, decoy_dir: str):
        self.carrier_image_dir = carrier_image_dir
        self.decoy_dir         = decoy_dir

    def _get_carrier_image(self) -> str:
        """Find the carrier image in carrier_images/."""
        for filename in os.listdir(self.carrier_image_dir):
            if filename.lower().endswith((".png", ".jpg", ".jpeg")):
                path = os.path.join(self.carrier_image_dir, filename)
                logger.info("Using carrier image: %s", path)
                return path
        raise FileNotFoundError(
            f"No carrier image found in {self.carrier_image_dir}. "
            f"Add a .png or .jpg file to carrier_images/"
        )

    def deploy(self, preservation_result: dict) -> dict:
        """
        Execute the full deception pipeline.

        Parameters
        ----------
        preservation_result : dict returned by PreservationEngine.run()

        Returns updated result dict with stego_path and decoy_path added.
        """
        session_id = preservation_result["session_id"]
        enc_path   = preservation_result["enc_path"]

        result = preservation_result.copy()
        result["stego_path"] = None
        result["decoy_path"] = None

        try:
            logger.info("=" * 55)
            logger.info("DECEPTION LAYER SESSION %s STARTED", session_id)
            logger.info("=" * 55)

            # ── Step 1: Embed evidence into carrier image ────────────
            carrier_path = self._get_carrier_image()
            stego_path   = embed_evidence(enc_path, carrier_path, session_id)
            result["stego_path"] = stego_path
            logger.info("Steganographic embedding complete")

            # ── Step 2: Generate and deploy decoy ───────────────────
            generator  = DecoyGenerator(decoy_dir=self.decoy_dir)
            decoy_path = generator.generate(session_id)
            result["decoy_path"] = decoy_path
            logger.info("Decoy evidence store deployed")

            # ── Step 3: Update completion log with layer 3 results ──
            completion_logger = CompletionLogger(log_dir=LOG_DIR)
            completion_logger.write(
                session_id      = session_id,
                trigger_time    = "see initial entry",
                completion_time = "layer 3 complete",
                elapsed_s       = preservation_result.get("elapsed_s", 0.0),
                enc_path        = enc_path,
                hash_hex        = preservation_result.get("hash_hex", "N/A"),
                hash_path       = preservation_result.get("hash_path", "N/A"),
                key_path        = preservation_result.get("key_path", "N/A"),
                stego_path      = stego_path,
                decoy_path      = decoy_path,
                success         = True,
            )

            logger.info("DECEPTION LAYER COMPLETE")
            logger.info("  Real evidence hidden in : %s", stego_path)
            logger.info("  Decoy deployed at       : %s", decoy_path)

        except Exception as e:
            logger.error("Deception layer failed: %s", e, exc_info=True)
            result["error"] = str(e)

        return result


def run_deception_pipeline(preservation_result: dict) -> dict:
    """
    Entry point called by the preservation pipeline.
    """
    layer = DeceptionLayer(
        carrier_image_dir=CARRIER_IMAGE_DIR,
        decoy_dir=DECOY_DIR,
    )
    return layer.deploy(preservation_result)