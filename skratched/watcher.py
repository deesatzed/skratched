from __future__ import annotations

import argparse
import json
import threading
import time
from pathlib import Path
from typing import Any, Callable

from .config import load_config
from .storage import SkratchedStore


SleepFn = Callable[[float], None]


def run_screenshot_watcher(
    store: SkratchedStore,
    directory: str | Path,
    *,
    project: str | None = None,
    interval_seconds: float = 5.0,
    limit: int = 10,
    max_cycles: int | None = None,
    stop_event: threading.Event | None = None,
    sleep: SleepFn = time.sleep,
) -> dict[str, Any]:
    if max_cycles is not None and max_cycles < 1:
        raise ValueError("max_cycles must be positive when provided")
    interval_seconds = max(0.0, float(interval_seconds))

    cycles = 0
    imported: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    stop_reason = "max_cycles" if max_cycles is not None else "running"

    while True:
        if stop_event is not None and stop_event.is_set():
            stop_reason = "stop_event"
            break
        if max_cycles is not None and cycles >= max_cycles:
            stop_reason = "max_cycles"
            break

        cycles += 1
        try:
            report = store.scan_screenshot_watch(directory, project=project, limit=limit)
            imported.extend(report.get("items", []))
            skipped.extend(report.get("skipped", []))
        except (OSError, ValueError) as exc:
            errors.append({"cycle": str(cycles), "error": str(exc)})

        if max_cycles is not None and cycles >= max_cycles:
            stop_reason = "max_cycles"
            break
        if stop_event is not None and stop_event.is_set():
            stop_reason = "stop_event"
            break
        if interval_seconds > 0:
            sleep(interval_seconds)

    resolved_directory = str(Path(directory).expanduser().resolve(strict=False))
    return {
        "directory": resolved_directory,
        "cycles": cycles,
        "imported_count": len(imported),
        "skipped_count": len(skipped),
        "error_count": len(errors),
        "items": imported,
        "skipped": skipped,
        "errors": errors,
        "stopped_reason": stop_reason,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local Skratched screenshot watcher.")
    parser.add_argument("directory", nargs="?", default=None)
    parser.add_argument("--config", default=None)
    parser.add_argument("--db", dest="db_path", default=None)
    parser.add_argument("--project", default=None)
    parser.add_argument("--interval", dest="watch_interval_seconds", type=float, default=None)
    parser.add_argument("--limit", dest="watch_limit", type=int, default=None)
    parser.add_argument("--max-cycles", type=int, default=None)
    args = parser.parse_args()

    cli = {key: value for key, value in vars(args).items() if value is not None and key != "project"}
    if args.directory is not None:
        cli["screenshot_watch_dir"] = args.directory
    config = load_config(cli=cli)

    store = SkratchedStore(config.db_path)
    try:
        report = run_screenshot_watcher(
            store,
            config.screenshot_watch_dir,
            project=args.project,
            interval_seconds=config.watch_interval_seconds,
            limit=config.watch_limit,
            max_cycles=config.max_watch_cycles,
        )
        print(json.dumps(report, indent=2, sort_keys=True))
    finally:
        store.close()


if __name__ == "__main__":
    main()
