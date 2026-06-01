"""
The detection daemon. Starts the inotify observer and watches
configured paths for suspicious activity.

Usage:
    python -m detection_layer.daemon          # run normally
    python -m detection_layer.daemon --test   # run self-test
"""

import argparse
import logging
import logging.handlers
import os
import signal
import sys
import time

from watchdog.observers import Observer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from config import WATCHED_PATHS, IGNORE_PATTERNS, LOG_FILE, LOG_DIR
from detection_layer.event_handler import ForensicEventHandler


def setup_logging(verbose=False):
    os.makedirs(LOG_DIR, exist_ok=True)
    level = logging.DEBUG if verbose else logging.INFO
    fmt = logging.Formatter(
        fmt="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler = logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3
    )
    file_handler.setFormatter(fmt)
    file_handler.setLevel(level)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(fmt)
    stream_handler.setLevel(level)

    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(file_handler)
    root.addHandler(stream_handler)


logger = logging.getLogger("eps.daemon")


def _placeholder_trigger(event, timestamp):
    """
    Called when a suspicious event is detected.
    Sends an alert email and logs the event.
    """
    logger.warning("=" * 55)
    logger.warning("  *** TRIGGER FIRED ***")
    logger.warning("  Event : %s", type(event).__name__)
    logger.warning("  Path  : %s", event.src_path)
    logger.warning("  Time  : %.3f", timestamp)
    logger.warning("=" * 55)

    # Send email alert
    from detection_layer.alerting import send_alert
    send_alert(
        event_type=type(event).__name__,
        event_path=event.src_path
    )


class DetectionDaemon:

    def __init__(self, trigger_callback=None, cooldown_s=5.0):
        self.trigger_callback = trigger_callback or _placeholder_trigger
        self.cooldown_s       = cooldown_s
        self.observers        = []
        self._running         = False

    def start(self):
        handler = ForensicEventHandler(
            trigger_callback=self.trigger_callback,
            ignore_patterns=IGNORE_PATTERNS,
            cooldown_s=self.cooldown_s,
        )

        for path in WATCHED_PATHS:
            if os.path.isfile(path):
                watch_path = os.path.dirname(path)
            elif os.path.isdir(path):
                watch_path = path
            else:
                logger.warning("Path does not exist, skipping: %s", path)
                continue

            observer = Observer()
            observer.schedule(handler, watch_path, recursive=True)
            observer.start()
            self.observers.append(observer)
            logger.info("Watching: %s", watch_path)

        self._running = True
        logger.info("Detection daemon started. Press Ctrl+C to stop.")

    def stop(self):
        self._running = False
        for obs in self.observers:
            obs.stop()
        for obs in self.observers:
            obs.join()
        logger.info("Detection daemon stopped.")

    def run_forever(self):
        self.start()

        def _shutdown(signum, frame):
            logger.info("Shutting down...")
            self.stop()
            sys.exit(0)

        signal.signal(signal.SIGINT,  _shutdown)
        signal.signal(signal.SIGTERM, _shutdown)

        while self._running:
            time.sleep(1)


def run_self_test():
    import tempfile
    import threading

    setup_logging(verbose=True)
    logger.info("Running detection layer self-test...")

    triggered = threading.Event()

    def test_trigger(event, ts):
        logger.info("Self-test: trigger fired for %s", event.src_path)
        triggered.set()

    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = os.path.join(tmpdir, "test_evidence.log")
        with open(test_file, "w") as f:
            f.write("simulated log entry\n")

        obs = Observer()
        handler = ForensicEventHandler(
            trigger_callback=test_trigger,
            ignore_patterns=[],
            cooldown_s=0.5,
        )
        obs.schedule(handler, tmpdir, recursive=False)
        obs.start()

        time.sleep(0.5)
        logger.info("Self-test: deleting %s", test_file)
        os.remove(test_file)

        fired = triggered.wait(timeout=5.0)
        obs.stop()
        obs.join()

    if fired:
        logger.info("Self-test PASSED")
        sys.exit(0)
    else:
        logger.error("Self-test FAILED")
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="EPS Detection Daemon")
    parser.add_argument("--test",    action="store_true", help="Run self-test and exit")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    parser.add_argument("--cooldown", type=float, default=5.0, help="Seconds between triggers")
    args = parser.parse_args()

    setup_logging(verbose=args.verbose)

    if args.test:
        run_self_test()
    else:
        daemon = DetectionDaemon(cooldown_s=args.cooldown)
        daemon.run_forever()