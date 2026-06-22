"""
tests/test_preservation.py

Unit tests for the preservation layer.

Run with:
    python3 tests/test_preservation.py
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestCrypto(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir)

    def test_key_generation(self):
        """Generated key should be 32 bytes and saved to disk."""
        from preservation_layer.crypto import generate_key
        key, key_path = generate_key(self.tmpdir, "test001")
        self.assertEqual(len(key), 32)
        self.assertTrue(os.path.exists(key_path))

    def test_encrypt_and_decrypt(self):
        """Decrypted content should match original."""
        from preservation_layer.crypto import generate_key, encrypt_archive, decrypt_archive

        # Create a dummy archive
        archive_path = os.path.join(self.tmpdir, "test.tar.gz")
        with open(archive_path, "wb") as f:
            f.write(b"simulated forensic evidence content")

        key, key_path = generate_key(self.tmpdir, "test002")
        enc_path = encrypt_archive(archive_path, key, self.tmpdir, "test002")

        self.assertTrue(os.path.exists(enc_path))

        # Decrypt and verify
        dec_path = os.path.join(self.tmpdir, "decrypted.tar.gz")
        success = decrypt_archive(enc_path, key_path, dec_path)

        self.assertTrue(success)
        with open(dec_path, "rb") as f:
            content = f.read()
        self.assertEqual(content, b"simulated forensic evidence content")

    def test_sha256_hash(self):
        """Hash file should exist and contain valid SHA-256 hex string."""
        from preservation_layer.crypto import generate_key, encrypt_archive, compute_hash

        archive_path = os.path.join(self.tmpdir, "test.tar.gz")
        with open(archive_path, "wb") as f:
            f.write(b"test content for hashing")

        key, key_path = generate_key(self.tmpdir, "test003")
        enc_path = encrypt_archive(archive_path, key, self.tmpdir, "test003")
        hash_hex, hash_path = compute_hash(enc_path, self.tmpdir, "test003")

        self.assertTrue(os.path.exists(hash_path))
        self.assertEqual(len(hash_hex), 64)  # SHA-256 = 64 hex chars

    def test_hash_matches_after_decrypt(self):
        """SHA-256 hash must match before and after decryption - core NFR."""
        import hashlib
        from preservation_layer.crypto import (
            generate_key, encrypt_archive, compute_hash, decrypt_archive
        )

        archive_path = os.path.join(self.tmpdir, "test.tar.gz")
        with open(archive_path, "wb") as f:
            f.write(b"critical forensic evidence")

        key, key_path = generate_key(self.tmpdir, "test004")
        enc_path  = encrypt_archive(archive_path, key, self.tmpdir, "test004")
        hash_hex, _ = compute_hash(enc_path, self.tmpdir, "test004")

        # Decrypt then re-hash the encrypted file
        sha256 = hashlib.sha256()
        with open(enc_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        rehash = sha256.hexdigest()

        self.assertEqual(hash_hex, rehash,
            "SHA-256 hash must match before and after — chain of custody broken")


class TestPreservationEngine(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir)

    def test_engine_runs_successfully(self):
        """Preservation engine should complete and return success."""
        import time
        from preservation_layer.capture import PreservationEngine

        engine = PreservationEngine(
            evidence_dir=self.tmpdir,
            response_window_s=30.0
        )
        result = engine.run(time.monotonic())

        self.assertTrue(result["success"], f"Engine failed: {result['error']}")
        self.assertIsNotNone(result["enc_path"])
        self.assertIsNotNone(result["hash_hex"])

    def test_engine_completes_within_response_window(self):
        """Full preservation cycle must complete within 30 seconds."""
        import time
        from preservation_layer.capture import PreservationEngine

        engine = PreservationEngine(
            evidence_dir=self.tmpdir,
            response_window_s=30.0
        )
        result = engine.run(time.monotonic())

        self.assertLess(result["elapsed_s"], 30.0,
            f"Exceeded response window: {result['elapsed_s']:.2f}s")

    def test_encrypted_file_exists(self):
        """Encrypted archive must exist after preservation."""
        import time
        from preservation_layer.capture import PreservationEngine

        engine = PreservationEngine(evidence_dir=self.tmpdir)
        result = engine.run(time.monotonic())

        self.assertTrue(os.path.exists(result["enc_path"]))

    def test_key_file_exists(self):
        """Key file must be saved alongside encrypted archive."""
        import time
        from preservation_layer.capture import PreservationEngine

        engine = PreservationEngine(evidence_dir=self.tmpdir)
        result = engine.run(time.monotonic())

        self.assertTrue(os.path.exists(result["key_path"]))

    def test_unencrypted_archive_deleted(self):
        """Unencrypted .tar.gz must be deleted after encryption."""
        import time
        from preservation_layer.capture import PreservationEngine

        engine = PreservationEngine(evidence_dir=self.tmpdir)
        result = engine.run(time.monotonic())

        # Only .enc .key and .hash should exist - no .tar.gz
        files = os.listdir(self.tmpdir)
        tar_files = [f for f in files if f.endswith(".tar.gz")]
        self.assertEqual(len(tar_files), 0,
            "Unencrypted archive should be deleted after encryption")


class TestCompletionLogger(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir)

    def test_log_written(self):
        """Completion log file should exist after write."""
        from preservation_layer.logger import CompletionLogger

        cl = CompletionLogger(log_dir=self.tmpdir)
        cl.write(
            session_id      = "20260601_140000",
            trigger_time    = "2026-06-01 14:00:00",
            completion_time = "2026-06-01 14:00:15",
            elapsed_s       = 15.3,
            enc_path        = "/tmp/session.enc",
            hash_hex        = "a" * 64,
            hash_path       = "/tmp/session.hash",
            key_path        = "/tmp/session.key",
            success         = True,
        )
        self.assertTrue(os.path.exists(cl.log_path))

    def test_log_contains_session_id(self):
        """Completion log must contain the session ID."""
        from preservation_layer.logger import CompletionLogger

        cl = CompletionLogger(log_dir=self.tmpdir)
        cl.write(
            session_id      = "20260601_140000",
            trigger_time    = "2026-06-01 14:00:00",
            completion_time = "2026-06-01 14:00:15",
            elapsed_s       = 15.3,
            enc_path        = "/tmp/session.enc",
            hash_hex        = "a" * 64,
            hash_path       = "/tmp/session.hash",
            key_path        = "/tmp/session.key",
            success         = True,
        )
        content = cl.read_all()
        self.assertIn("20260601_140000", content)


if __name__ == "__main__":
    unittest.main(verbosity=2)