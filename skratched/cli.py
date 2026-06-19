from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_server_main():
    server_path = Path(__file__).resolve().parents[1] / "server.py"
    spec = importlib.util.spec_from_file_location("_skratched_server_entrypoint", server_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load Skratched server from {server_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.main


def main() -> None:
    server_main = _load_server_main()
    server_main()


if __name__ == "__main__":
    main()
