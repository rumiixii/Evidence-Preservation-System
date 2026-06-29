import hashlib
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestDecoyGenerator(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir)

    def test_decoy_directory_created(self):
        from deception_layer.decoy import DecoyGenerator
        gen = DecoyGenerator(decoy_dir=self.tmpdir)
        decoy_path = gen.generate("test001")
        self.assertTrue(os.path.exists(decoy_path))

    def test_decoy_contains_expected_files(self):
        from deception_layer.decoy import DecoyGenerator
        gen = DecoyGenerator(decoy_dir=self.tmpdir)
        decoy_path = gen.generate("test002")
        for filename in ["processes.txt", "network.txt", "users.txt", "bash_history.txt", "var_log"]:
            self.assertTrue(os.path.exists(os.path.join(decoy_path, filename)))

    def test_decoy_contains_fake_encrypted_archive(self):
        from deception_layer.decoy import DecoyGenerator
        gen = DecoyGenerator(decoy_dir=self.tmpdir)
        decoy_path = gen.generate("test003")
        enc_files = [f for f in os.listdir(decoy_path) if f.endswith(".enc")]
        self.assertTrue(len(enc_files) > 0)

    def test_decoy_logs_are_not_empty(self):
        from deception_layer.decoy import DecoyGenerator
        gen = DecoyGenerator(decoy_dir=self.tmpdir)
        decoy_path = gen.generate("test004")
        syslog_path = os.path.join(decoy_path, "var_log", "syslog")
        self.assertTrue(os.path.exists(syslog_path))
        with open(syslog_path) as f:
            self.assertGreater(len(f.read()), 0)


class TestSteganography(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        from PIL import Image
        img = Image.new("RGB", (1920, 1080), color=(100, 149, 237))
        self.carrier_path = os.path.join(self.tmpdir, "carrier.png")
        img.save(self.carrier_path)
        self.payload_path = os.path.join(self.tmpdir, "session_test001.enc")
        with open(self.payload_path, "wb") as f:
            f.write(os.urandom(1024))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir)

    def test_embed_produces_stego_image(self):
        from deception_layer.steganography import embed_evidence
        stego_path = embed_evidence(self.payload_path, self.carrier_path, "test001")
        self.assertTrue(os.path.exists(stego_path))

    def test_stego_image_same_size_as_carrier(self):
        from PIL import Image
        from deception_layer.steganography import embed_evidence
        stego_path = embed_evidence(self.payload_path, self.carrier_path, "test002")
        self.assertEqual(Image.open(self.carrier_path).size, Image.open(stego_path).size)

    def test_extract_recovers_original_payload(self):
        from deception_layer.steganography import embed_evidence, extract_evidence
        stego_path = embed_evidence(self.payload_path, self.carrier_path, "test003")
        extracted_path = os.path.join(self.tmpdir, "extracted.enc")
        self.assertTrue(extract_evidence(stego_path, extracted_path))
        self.assertEqual(open(self.payload_path, "rb").read(), open(extracted_path, "rb").read())

    def test_hash_matches_after_extraction(self):
        from deception_layer.steganography import embed_evidence, extract_evidence
        original_hash = hashlib.sha256(open(self.payload_path, "rb").read()).hexdigest()
        stego_path = embed_evidence(self.payload_path, self.carrier_path, "test004")
        extracted_path = os.path.join(self.tmpdir, "extracted.enc")
        extract_evidence(stego_path, extracted_path)
        extracted_hash = hashlib.sha256(open(extracted_path, "rb").read()).hexdigest()
        self.assertEqual(original_hash, extracted_hash)


class TestDeceptionPipeline(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        from PIL import Image
        carrier_dir = os.path.join(self.tmpdir, "carrier_images")
        os.makedirs(carrier_dir, exist_ok=True)
        img = Image.new("RGB", (1920, 1080), color=(100, 149, 237))
        self.carrier_path = os.path.join(carrier_dir, "carrier.png")
        img.save(self.carrier_path)
        self.carrier_dir = carrier_dir
        enc_dir = os.path.join(self.tmpdir, "evidence_store")
        os.makedirs(enc_dir, exist_ok=True)
        enc_path = os.path.join(enc_dir, "session_test001.enc")
        with open(enc_path, "wb") as f:
            f.write(os.urandom(1024))
        self.preservation_result = {
            "success": True,
            "session_id": "test001",
            "enc_path": enc_path,
            "hash_hex": "a" * 64,
            "hash_path": os.path.join(enc_dir, "session_test001.hash"),
            "key_path": os.path.join(enc_dir, "session_test001.key"),
            "elapsed_s": 5.0,
            "error": None,
        }

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir)

    def test_full_pipeline_succeeds(self):
        from deception_layer.pipeline import DeceptionLayer
        layer = DeceptionLayer(carrier_image_dir=self.carrier_dir, decoy_dir=os.path.join(self.tmpdir, "decoy"))
        result = layer.deploy(self.preservation_result)
        self.assertIsNotNone(result["stego_path"])
        self.assertIsNotNone(result["decoy_path"])

    def test_stego_image_exists(self):
        from deception_layer.pipeline import DeceptionLayer
        layer = DeceptionLayer(carrier_image_dir=self.carrier_dir, decoy_dir=os.path.join(self.tmpdir, "decoy"))
        result = layer.deploy(self.preservation_result)
        self.assertTrue(os.path.exists(result["stego_path"]))

    def test_decoy_exists(self):
        from deception_layer.pipeline import DeceptionLayer
        layer = DeceptionLayer(carrier_image_dir=self.carrier_dir, decoy_dir=os.path.join(self.tmpdir, "decoy"))
        result = layer.deploy(self.preservation_result)
        self.assertTrue(os.path.exists(result["decoy_path"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
