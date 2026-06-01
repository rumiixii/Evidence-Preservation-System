"""
tests/test_detection.py

Unit tests for the detection layer.

Run with:
    python tests/test_detection.py
"""

import os
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from watchdog.observers import Observer
from detection_layer.event_handler import ForensicEventHandler


class TestDetectionLayer(unittest.TestCase):

    def _start_watcher(self, watch_dir, trigger_fn, ignore=None, cooldown=0.3):
        handler = ForensicEventHandler(
            trigger_callback=trigger_fn,
            ignore_patterns=ignore or [],
            cooldown_s=cooldown,
        )
        obs = Observer()
        obs.schedule(handler, watch_dir, recursive=True)
        obs.start()
        time.sleep(0.3)
        return obs

    def test_deletion_fires_trigger(self):
        """Deleting a file should fire the trigger."""
        triggered = threading.Event()

        def cb(event, ts):
            triggered.set()

        with tempfile.TemporaryDirectory() as tmpdir:
            target = os.path.join(tmpdir, "syslog")
            with open(target, "w") as f:
                f.write("May 31 login attempt\n")

            obs = self._start_watcher(tmpdir, cb)
            os.remove(target)
            fired = triggered.wait(timeout=5.0)
            obs.stop()
            obs.join()

        self.assertTrue(fired, "Trigger should fire when a file is deleted")

    def test_ignored_pattern_suppresses_trigger(self):
        """Files matching ignore patterns should not fire the trigger."""
        triggered = threading.Event()

        def cb(event, ts):
            triggered.set()

        with tempfile.TemporaryDirectory() as tmpdir:
            target = os.path.join(tmpdir, "session.lock")
            with open(target, "w") as f:
                f.write("lock\n")

            obs = self._start_watcher(tmpdir, cb, ignore=["*.lock"])
            os.remove(target)
            fired = triggered.wait(timeout=2.0)
            obs.stop()
            obs.join()

        self.assertFalse(fired, "Trigger should NOT fire for ignored patterns")

    def test_cooldown_prevents_duplicate_triggers(self):
        """Multiple rapid deletions should only fire one trigger."""
        trigger_times = []

        def cb(event, ts):
            trigger_times.append(ts)

        with tempfile.TemporaryDirectory() as tmpdir:
            obs = self._start_watcher(tmpdir, cb, cooldown=2.0)

            for i in range(3):
                f = os.path.join(tmpdir, f"log_{i}.txt")
                with open(f, "w") as fh:
                    fh.write("x")
                os.remove(f)
                time.sleep(0.1)

            time.sleep(1.0)
            obs.stop()
            obs.join()

        self.assertEqual(len(trigger_times), 1,
            f"Cooldown should suppress duplicates, got {len(trigger_times)} triggers")

    def test_modification_fires_trigger(self):
        """Truncating a log file should fire the trigger."""
        triggered = threading.Event()

        def cb(event, ts):
            triggered.set()

        with tempfile.TemporaryDirectory() as tmpdir:
            target = os.path.join(tmpdir, "auth.log")
            with open(target, "w") as f:
                f.write("original content\n")

            obs = self._start_watcher(tmpdir, cb)
            with open(target, "w") as f:
                f.write("")
            fired = triggered.wait(timeout=5.0)
            obs.stop()
            obs.join()

        self.assertTrue(fired, "Trigger should fire when a file is modified")

    def test_trigger_receives_correct_data(self):
        """Trigger callback should receive the event object and a timestamp."""
        received = {}

        def cb(event, ts):
            received["event"] = event
            received["ts"]    = ts

        with tempfile.TemporaryDirectory() as tmpdir:
            target = os.path.join(tmpdir, "kern.log")
            with open(target, "w") as f:
                f.write("kernel message\n")

            obs = self._start_watcher(tmpdir, cb)
            os.remove(target)
            time.sleep(2.0)
            obs.stop()
            obs.join()

        self.assertIn("event", received, "Callback should have been called")
        self.assertIsInstance(received["ts"], float)


if __name__ == "__main__":
    unittest.main(verbosity=2)