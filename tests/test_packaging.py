import importlib
import pathlib
import subprocess
import sys
import tomllib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class PackagingTests(unittest.TestCase):
    def test_pyproject_defines_skratched_server_console_entrypoint(self):
        pyproject = ROOT / "pyproject.toml"

        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))

        self.assertEqual(data["project"]["name"], "skratched")
        self.assertEqual(data["project"]["version"], "0.1.0")
        self.assertEqual(data["project"]["scripts"]["skratched-server"], "skratched.cli:main")
        self.assertEqual(data["project"]["scripts"]["skratched-mcp"], "skratched.mcp_server:main")
        self.assertIn("mcp>=1.28.0", data["project"]["dependencies"])
        self.assertIn("server", data["tool"]["setuptools"]["py-modules"])
        self.assertIn("static/*.html", data["tool"]["setuptools"]["data-files"]["static"])
        self.assertIn("static/*.js", data["tool"]["setuptools"]["data-files"]["static"])
        self.assertIn("static/*.css", data["tool"]["setuptools"]["data-files"]["static"])

    def test_console_entrypoint_imports_without_starting_server(self):
        module = importlib.import_module("skratched.cli")

        self.assertTrue(callable(module.main))

    def test_console_entrypoint_help_runs_after_editable_install(self):
        result = subprocess.run(
            [sys.executable, "-m", "skratched.cli", "--help"],
            check=True,
            capture_output=True,
            text=True,
        )

        self.assertIn("Run the local Skratched app", result.stdout)

    def test_mcp_server_module_imports_without_starting_server(self):
        module = importlib.import_module("skratched.mcp_server")

        self.assertTrue(callable(module.main))
        self.assertTrue(callable(module.build_app))


if __name__ == "__main__":
    unittest.main()
