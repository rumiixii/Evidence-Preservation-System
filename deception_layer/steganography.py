"""
deception_layer/steganography.py

Handles LSB steganographic embedding and extraction
using the Stegano library.

The encrypted evidence archive is embedded into a carrier
image using Least Significant Bit encoding. The resulting
stego-image is visually indistinguishable from the original.
"""

import logging
import os

logger = logging.getLogger("eps.deception.steganography")

# Inconspicuous storage path - looks like a system cache directory
# An attacker would not think to look here
CONCEALMENT_DIR = os.path.expanduser("~/.cache/thumbnails/large")


def embed_evidence(enc_path: str, carrier_path: str, session_id: str) -> str:
    """
    Embed the encrypted archive into a carrier image using LSB steganography.

    Parameters
    ----------
    enc_path     : path to the encrypted archive (.enc file)
    carrier_path : path to the original carrier image (.png)
    session_id   : unique session identifier for naming the stego-image

    Returns path to the stego-image.
    """
    try:
        from stegano import lsb
    except ImportError:
        raise ImportError("Stegano is required. Install with: pip install stegano")

    # Read encrypted archive as bytes then encode as string for embedding
    with open(enc_path, "rb") as f:
        enc_bytes = f.read()

    # Convert bytes to a string representation for LSB embedding
    # We encode as latin-1 which preserves all byte values 0-255
    enc_str = enc_bytes.decode("latin-1")

    # Check carrier image capacity
    _check_capacity(carrier_path, len(enc_bytes))

    # Create concealment directory if it doesn't exist
    os.makedirs(CONCEALMENT_DIR, exist_ok=True)

    # Save stego-image with an innocuous name
    stego_path = os.path.join(CONCEALMENT_DIR, f"{session_id}.png")

    logger.info("Embedding %d bytes into carrier image...", len(enc_bytes))

    secret = lsb.hide(carrier_path, enc_str)
    secret.save(stego_path)

    logger.info("Stego-image saved → %s", stego_path)
    return stego_path


def extract_evidence(stego_path: str, output_enc_path: str) -> bool:
    """
    Extract the hidden evidence from a stego-image.
    Used by the investigator during evidence recovery.

    Parameters
    ----------
    stego_path      : path to the stego-image
    output_enc_path : path where the extracted .enc file will be saved

    Returns True on success, False on failure.
    """
    try:
        from stegano import lsb
    except ImportError:
        raise ImportError("Stegano is required.")

    try:
        logger.info("Extracting hidden evidence from %s", stego_path)

        enc_str   = lsb.reveal(stego_path)
        enc_bytes = enc_str.encode("latin-1")

        with open(output_enc_path, "wb") as f:
            f.write(enc_bytes)

        logger.info("Evidence extracted → %s", output_enc_path)
        return True

    except Exception as e:
        logger.error("Extraction failed: %s", e)
        return False


def _check_capacity(carrier_path: str, payload_bytes: int) -> None:
    """
    Verify the carrier image is large enough to hold the payload.
    LSB in RGB PNG = width * height * 3 bits = width * height * 3 / 8 bytes.
    """
    try:
        from PIL import Image
        img = Image.open(carrier_path)
        width, height = img.size
        # Each pixel holds 3 bits (one per RGB channel)
        capacity_bytes = (width * height * 3) // 8
        logger.info(
            "Carrier capacity: %d bytes | Payload: %d bytes",
            capacity_bytes, payload_bytes
        )
        if payload_bytes > capacity_bytes:
            raise ValueError(
                f"Payload too large: {payload_bytes} bytes "
                f"exceeds carrier capacity of {capacity_bytes} bytes. "
                f"Use a larger carrier image."
            )
    except ImportError:
        logger.warning("Pillow not available — skipping capacity check")