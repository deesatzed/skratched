from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .analyze import redact_text


DEFAULT_CONFIG: dict[str, Any] = {
    "host": "127.0.0.1",
    "port": 8787,
    "db_path": "data/skratched.db",
    "screenshot_watch_dir": "~/Desktop",
    "watch_interval_seconds": 5.0,
    "watch_limit": 10,
    "max_watch_cycles": None,
    "optional_ai_label": "",
}

ENV_FIELDS = {
    "host": "SKRATCHED_HOST",
    "port": "SKRATCHED_PORT",
    "db_path": "SKRATCHED_DB",
    "screenshot_watch_dir": "SKRATCHED_SCREENSHOT_DIR",
    "watch_interval_seconds": "SKRATCHED_WATCH_INTERVAL",
    "watch_limit": "SKRATCHED_WATCH_LIMIT",
    "max_watch_cycles": "SKRATCHED_MAX_CYCLES",
    "optional_ai_label": "SKRATCHED_OPTIONAL_AI_LABEL",
}


@dataclass(frozen=True)
class SkratchedConfig:
    host: str
    port: int
    db_path: Path
    screenshot_watch_dir: Path
    watch_interval_seconds: float
    watch_limit: int
    max_watch_cycles: int | None
    optional_ai_label: str
    sources: dict[str, str]

    def safe_summary(self) -> dict[str, Any]:
        return {
            "host": redact_text(self.host),
            "port": self.port,
            "db_path": redact_text(str(self.db_path)),
            "screenshot_watch_dir": redact_text(str(self.screenshot_watch_dir)),
            "watch_interval_seconds": self.watch_interval_seconds,
            "watch_limit": self.watch_limit,
            "max_watch_cycles": self.max_watch_cycles,
            "optional_ai_label": redact_text(self.optional_ai_label),
            "sources": dict(self.sources),
            "precedence": ["cli", "env", "config", "default"],
        }


def _resolve_path(value: Any, *, base_dir: Path) -> Path:
    raw = str(value or "").strip()
    if not raw:
        raw = "."
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = base_dir / path
    return path.resolve(strict=False)


def _coerce_int(field: str, value: Any, *, minimum: int, maximum: int | None = None) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be an integer")
    try:
        coerced = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be an integer") from exc
    if coerced < minimum:
        raise ValueError(f"{field} must be at least {minimum}")
    if maximum is not None and coerced > maximum:
        raise ValueError(f"{field} must be at most {maximum}")
    return coerced


def _coerce_optional_int(field: str, value: Any, *, minimum: int) -> int | None:
    if value is None or value == "":
        return None
    return _coerce_int(field, value, minimum=minimum)


def _coerce_float(field: str, value: Any, *, minimum: float) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a number")
    try:
        coerced = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be a number") from exc
    if coerced < minimum:
        raise ValueError(f"{field} must be at least {minimum:g}")
    return coerced


def _load_config_file(config_path: Path | None, *, base_dir: Path) -> tuple[dict[str, Any], Path | None]:
    path = config_path
    if path is None:
        path = base_dir / "data" / "skratched.json"
    path = path.expanduser()
    if not path.is_absolute():
        path = base_dir / path
    if path.is_symlink():
        raise ValueError("config path must not be a symlink")
    if not path.exists():
        return {}, path.resolve(strict=False)
    if not path.is_file():
        raise ValueError("config path must be a file")
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"config file is invalid JSON: {exc.msg}") from exc
    if not isinstance(loaded, dict):
        raise ValueError("config file must contain a JSON object")
    return loaded, path.resolve(strict=False)


def _apply_layer(
    values: dict[str, Any],
    sources: dict[str, str],
    layer: Mapping[str, Any],
    *,
    source_name: str,
) -> None:
    for field in DEFAULT_CONFIG:
        if field not in layer:
            continue
        value = layer[field]
        if value is None or value == "":
            continue
        values[field] = value
        sources[field] = source_name


def _env_layer(env: Mapping[str, str]) -> dict[str, Any]:
    layer: dict[str, Any] = {}
    for field, name in ENV_FIELDS.items():
        if name in env:
            layer[field] = env[name]
    return layer


def load_config(
    *,
    cli: Mapping[str, Any] | None = None,
    env: Mapping[str, str] | None = None,
    config_path: str | Path | None = None,
    base_dir: str | Path | None = None,
) -> SkratchedConfig:
    base = Path(base_dir or Path.cwd()).expanduser().resolve(strict=False)
    environ = os.environ if env is None else env
    cli_values = dict(cli or {})
    chosen_config = config_path or cli_values.pop("config", None) or environ.get("SKRATCHED_CONFIG")
    file_values, _ = _load_config_file(Path(chosen_config) if chosen_config else None, base_dir=base)

    values = dict(DEFAULT_CONFIG)
    sources = {field: "default" for field in DEFAULT_CONFIG}
    _apply_layer(values, sources, file_values, source_name="config")
    _apply_layer(values, sources, _env_layer(environ), source_name="env")
    _apply_layer(values, sources, cli_values, source_name="cli")

    return SkratchedConfig(
        host=str(values["host"]),
        port=_coerce_int("port", values["port"], minimum=1, maximum=65535),
        db_path=_resolve_path(values["db_path"], base_dir=base),
        screenshot_watch_dir=_resolve_path(values["screenshot_watch_dir"], base_dir=base),
        watch_interval_seconds=_coerce_float("watch_interval_seconds", values["watch_interval_seconds"], minimum=0),
        watch_limit=_coerce_int("watch_limit", values["watch_limit"], minimum=1, maximum=100),
        max_watch_cycles=_coerce_optional_int("max_watch_cycles", values["max_watch_cycles"], minimum=1),
        optional_ai_label=str(values["optional_ai_label"] or ""),
        sources=sources,
    )


def save_config(path: str | Path, data: Mapping[str, Any]) -> Path:
    target = Path(path).expanduser()
    if target.is_symlink():
        raise ValueError("config path must not be a symlink")
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_suffix(target.suffix + ".tmp")
    encoded = json.dumps(dict(data), indent=2, sort_keys=True) + "\n"
    with open(temp, "w", encoding="utf-8") as handle:
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temp, 0o600)
    os.replace(temp, target)
    os.chmod(target, 0o600)
    return target
