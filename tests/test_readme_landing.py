import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
ASSETS = ROOT / "docs" / "assets"


class ReadmeLandingTests(unittest.TestCase):
    def test_readme_is_benefit_led_landing_page_with_competitive_positioning(self):
        text = README.read_text(encoding="utf-8")

        required_sections = [
            "## Why Skratched Exists",
            "## Why Users Want It",
            "## Screenshots",
            "## How Skratched Beats the Usual Stack",
            "## Feature Map",
            "## Quick Start",
        ]
        for section in required_sections:
            with self.subTest(section=section):
                self.assertIn(section, text)

        required_phrases = [
            "local-first",
            "experiential memory",
            "redacted by default",
            "no vector database",
            "workspace scout",
            "metadata-only",
            "approval-gated",
            "user-approved root",
            "note apps",
            "snippet managers",
            "password managers",
            "file search tools",
            "ai memory tools",
        ]
        lower = text.lower()
        for phrase in required_phrases:
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, lower)

    def test_readme_references_existing_png_screenshots(self):
        text = README.read_text(encoding="utf-8")
        screenshots = [
            ASSETS / "skratched-workspace.png",
            ASSETS / "skratched-workspace-scout.png",
            ASSETS / "skratched-context-map.png",
            ASSETS / "skratched-redacted-export.png",
        ]

        for screenshot in screenshots:
            with self.subTest(screenshot=screenshot.name):
                relative = screenshot.relative_to(ROOT).as_posix()
                self.assertIn(relative, text)
                self.assertTrue(screenshot.exists(), f"{relative} does not exist")
                self.assertEqual(screenshot.read_bytes()[:8], b"\x89PNG\r\n\x1a\n")


if __name__ == "__main__":
    unittest.main()
