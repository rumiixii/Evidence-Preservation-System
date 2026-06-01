"""
detection_layer/event_handler.py

Watches the file system using inotify and fires a trigger
when suspicious activity is detected.
"""

import fnmatch
import logging
import os
import time
from watchdog.events import FileSystemEventHandler

logger = logging.getLogger("eps.detection")


class ForensicEventHandler(FileSystemEventHandler):

    def __init__(self, trigger_callback, ignore_patterns=None, cooldown_s=5.0):
        super().__init__()
        self.trigger_callback   = trigger_callback
        self.ignore_patterns    = ignore_patterns or []
        self.cooldown_s         = cooldown_s
        self._last_trigger_time = 0.0
        self._trigger_count     = 0

    def on_deleted(self, event):
        self._handle(event)

    def on_modified(self, event):
        self._handle(event)

    def on_moved(self, event):
        self._handle(event)

    def _handle(self, event):
        # Skip directory-level noise
        if event.is_directory:
            return

        path = event.src_path

        if self._is_ignored(path):
            logger.debug("IGNORED: %s", path)
            return

        if self._is_benign_rotation(event):
            logger.debug("LOG ROTATION: %s", path)
            return

        logger.warning("SUSPICIOUS: %s on %s", type(event).__name__, path)
        self._fire_trigger(event)

    def _is_ignored(self, path):
        for pattern in self.ignore_patterns:
            if fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(os.path.basename(path), pattern):
                return True
        return False

    def _is_benign_rotation(self, event):
        from watchdog.events import FileMovedEvent
        if isinstance(event, FileMovedEvent):
            src  = event.src_path
            dest = getattr(event, "dest_path", "")
            if "/var/log" in src and "/var/log" in dest:
                return True
        return False

    def _fire_trigger(self, event):
        now = time.monotonic()
        if now - self._last_trigger_time < self.cooldown_s:
            logger.info("Cooldown active - trigger suppressed for %s", event.src_path)
            return

        self._last_trigger_time = now
        self._trigger_count    += 1

        logger.warning("TRIGGER #%d fired for %s", self._trigger_count, event.src_path)

        try:
            self.trigger_callback(event, now)
        except Exception as exc:
            logger.error("Trigger callback error: %s", exc, exc_info=True)