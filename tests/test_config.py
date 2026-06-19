import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from skratched.config import DEFAULT_CONFIG, load_config, save_config


class ConfigTests(unittest.TestCase):
    def test_config_precedence_is_cli_env_file_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = root / "skratched.json"
            config_path.write_text(
                json.dumps(
                    {
                        "host": "0.0.0.0",
                        "port": 9001,
                        "db_path": "from-file.db",
                        "screenshot_watch_dir": "file-shots",
                        "watch_interval_seconds": 7,
                        "watch_limit": 20,
                    }
                ),
                encoding="utf-8",
            )

            config = load_config(
                cli={
                    "port": 9100,
                    "db_path": root / "from-cli.db",
                },
                env={
                    "SKRATCHED_HOST": "127.0.0.2",
                    "SKRATCHED_DB": str(root / "from-env.db"),
                    "SKRATCHED_SCREENSHOT_DIR": str(root / "env-shots"),
                    "SKRATCHED_WATCH_LIMIT": "30",
                },
                config_path=config_path,
                base_dir=root,
            )

            self.assertEqual(config.host, "127.0.0.2")
            self.assertEqual(config.port, 9100)
            self.assertEqual(config.db_path, (root / "from-cli.db").resolve(strict=False))
            self.assertEqual(config.screenshot_watch_dir, (root / "env-shots").resolve(strict=False))
            self.assertEqual(config.watch_interval_seconds, 7)
            self.assertEqual(config.watch_limit, 30)
            self.assertEqual(config.sources["host"], "env")
            self.assertEqual(config.sources["port"], "cli")
            self.assertEqual(config.sources["db_path"], "cli")
            self.assertEqual(config.sources["watch_interval_seconds"], "config")
            self.assertEqual(config.sources["watch_limit"], "env")

    def test_missing_config_file_falls_back_to_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = load_config(config_path=root / "missing.json", env={}, base_dir=root)

            self.assertEqual(config.host, DEFAULT_CONFIG["host"])
            self.assertEqual(config.port, DEFAULT_CONFIG["port"])
            self.assertEqual(config.db_path, (root / DEFAULT_CONFIG["db_path"]).resolve(strict=False))
            self.assertEqual(config.watch_limit, DEFAULT_CONFIG["watch_limit"])
            self.assertTrue(all(source == "default" for source in config.sources.values()))

    def test_config_summary_redacts_secret_shaped_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = load_config(
                cli={"optional_ai_label": "OpenRouter sk-or-v1-configcccccccccccccccccccccccccccccccc"},
                env={},
                base_dir=root,
            )

            summary = config.safe_summary()
            encoded = json.dumps(summary)
            self.assertIn("[REDACTED:openrouter_key]", encoded)
            self.assertNotIn("sk-or-v1-config", encoded)
            self.assertEqual(summary["sources"]["optional_ai_label"], "cli")

    def test_save_config_uses_atomic_owner_only_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "config" / "skratched.json"

            save_config(path, {"host": "127.0.0.1", "port": 8787})

            self.assertTrue(path.exists())
            self.assertFalse(path.with_suffix(".json.tmp").exists())
            mode = stat.S_IMODE(path.stat().st_mode)
            self.assertEqual(mode, 0o600)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["port"], 8787)

    def test_config_rejects_bad_numeric_values_and_symlink_config_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaisesRegex(ValueError, "port"):
                load_config(env={"SKRATCHED_PORT": "not-a-port"}, base_dir=root)

            target = root / "real.json"
            target.write_text("{}", encoding="utf-8")
            link = root / "linked.json"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks are unavailable on this filesystem")

            with self.assertRaisesRegex(ValueError, "symlink"):
                load_config(config_path=link, env={}, base_dir=root)


if __name__ == "__main__":
    unittest.main()
