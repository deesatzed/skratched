import tempfile
import unittest
from pathlib import Path

from skratched.storage import SkratchedStore
from skratched.watcher import run_screenshot_watcher


class ScreenshotWatcherTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = SkratchedStore(self.root / "skratched.db")

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_background_watcher_imports_screenshot_from_later_poll_cycle(self):
        watch_dir = self.root / "screenshots"
        watch_dir.mkdir()
        screenshot = watch_dir / "Screenshot watcher later.png"

        sleep_calls = []

        def fake_sleep(seconds):
            sleep_calls.append(seconds)
            screenshot.write_bytes(b"\x89PNG\r\n\x1a\nwatcher-later-image")

        report = run_screenshot_watcher(
            self.store,
            watch_dir,
            project="watcher",
            interval_seconds=0.01,
            max_cycles=2,
            sleep=fake_sleep,
        )

        self.assertEqual(report["cycles"], 2)
        self.assertEqual(report["imported_count"], 1)
        self.assertEqual(report["skipped_count"], 0)
        self.assertEqual(report["error_count"], 0)
        self.assertEqual(report["stopped_reason"], "max_cycles")
        self.assertEqual(sleep_calls, [0.01])
        self.assertEqual(report["items"][0]["category"], "screenshots-work")
        self.assertEqual(report["items"][0]["facets"]["observed_path"], str(screenshot.resolve()))
        self.assertEqual(self.store.count_rows("artifacts"), 1)

    def test_background_watcher_tracks_duplicate_skips_across_cycles(self):
        watch_dir = self.root / "screenshots"
        watch_dir.mkdir()
        screenshot = watch_dir / "Screenshot watcher duplicate.png"
        screenshot.write_bytes(b"\x89PNG\r\n\x1a\nwatcher-duplicate-image")

        report = run_screenshot_watcher(
            self.store,
            watch_dir,
            project="watcher",
            interval_seconds=0,
            max_cycles=2,
        )

        self.assertEqual(report["cycles"], 2)
        self.assertEqual(report["imported_count"], 1)
        self.assertEqual(report["skipped_count"], 1)
        self.assertEqual(report["skipped"][0]["reason"], "duplicate_artifact_hash")
        self.assertEqual(self.store.count_rows("artifacts"), 1)

