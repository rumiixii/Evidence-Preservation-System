"""
preservation_layer/crypto.py

Handles AES-256 encryption, SHA-256 integrity hashing,
and encryption key generation for the preservation layer.

Key design:
- A fresh AES-256 key is generated per capture session
- The key is saved to evidence_store/ alongside the encrypted archive
- SHA-256 hash is computed on the encrypted archive and saved separately
- The investigator needs the .key file to decrypt and the .hash file to verify
"""

import hashlib
import logging
import os
from datetime import datetime

logger = logging.getLogger("eps.preservation.crypto")


def generate_key(evidence_dir: str, session_id: str) -> tuple[bytes, str]:
    """
    Generate a fresh 32-byte AES-256 key for this capture session.
    Save it to evidence_dir as session_<id>.key

    Returns (key_bytes, key_path)
    """
    key = os.urandom(32)  # 256 bits
    key_path = os.path.join(evidence_dir, f"session_{session_id}.key")

    with open(key_path, "wb") as f:
        f.write(key)

    logger.info("AES-256 key generated and saved to %s", key_path)
    return key, key_path


def encrypt_archive(archive_path: str, key: bytes, evidence_dir: str, session_id: str) -> str:
    """
    Encrypt a .tar.gz archive using AES-256 in EAX mode.
    Saves the encrypted file as session_<id>.enc in evidence_dir.

    EAX mode provides both confidentiality and integrity (authenticated encryption).

    Returns path to the encrypted file.
    """
    try:
        from Crypto.Cipher import AES
    except ImportError:
        raise ImportError(
            "PyCryptodome is required. Install with: pip install pycryptodome"
        )

    enc_path = os.path.join(evidence_dir, f"session_{session_id}.enc")

    with open(archive_path, "rb") as f:
        plaintext = f.read()

    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    # Write: nonce (16 bytes) + tag (16 bytes) + ciphertext
    with open(enc_path, "wb") as f:
        f.write(cipher.nonce)
        f.write(tag)
        f.write(ciphertext)

    logger.info("Archive encrypted → %s", enc_path)
    return enc_path


def compute_hash(enc_path: str, evidence_dir: str, session_id: str) -> tuple[str, str]:
    """
    Compute SHA-256 hash of the encrypted archive.
    Save it to session_<id>.hash in evidence_dir.

    Returns (hash_hex_string, hash_file_path)
    """
    sha256 = hashlib.sha256()

    with open(enc_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)

    hash_hex = sha256.hexdigest()
    hash_path = os.path.join(evidence_dir, f"session_{session_id}.hash")

    with open(hash_path, "w") as f:
        f.write(f"{hash_hex}  {os.path.basename(enc_path)}\n")

    logger.info("SHA-256 hash: %s", hash_hex)
    logger.info("Hash saved → %s", hash_path)
    return hash_hex, hash_path


def decrypt_archive(enc_path: str, key_path: str, output_path: str) -> bool:
    """
    Decrypt an encrypted archive for the investigator.
    Used during evidence recovery — not called during preservation.

    Returns True on success, False on failure.
    """
    try:
        from Crypto.Cipher import AES
    except ImportError:
        raise ImportError("PyCryptodome is required.")

    try:
        with open(key_path, "rb") as f:
            key = f.read()

        with open(enc_path, "rb") as f:
            nonce      = f.read(16)
            tag        = f.read(16)
            ciphertext = f.read()

        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        with open(output_path, "wb") as f:
            f.write(plaintext)

        logger.info("Archive decrypted → %s", output_path)
        return True

    except ValueError as e:
        logger.error("Decryption failed — archive may be corrupted: %s", e)
        return False
    except Exception as e:
        logger.error("Unexpected decryption error: %s", e)
        return False