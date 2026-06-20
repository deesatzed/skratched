from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Callable

from .storage import SkratchedStore

ALLOWED_ROOTS_ENV = "SKRATCHED_MCP_ALLOWED_ROOTS"


def skratched_health(*, store: SkratchedStore) -> dict[str, Any]:
    """Cheap pre-flight check that the local Skratched store is reachable and healthy."""
    return store.health_report()


def skratched_search(query: str, *, limit: int = 10, store: SkratchedStore) -> dict[str, Any]:
    """Search redacted Skratched memory. Call this before assuming something hasn't been solved before."""
    return {"query": query, "results": store.search(query, limit=limit)}


def skratched_context(item_id: str, *, store: SkratchedStore) -> dict[str, Any]:
    """Get the associated context graph (links, duplicates, neighbors) for a search hit."""
    if not item_id:
        raise ValueError("item_id is required")
    try:
        return store.context_graph(item_id)
    except KeyError as exc:
        raise ValueError(f"unknown item_id: {item_id}") from exc


def skratched_capture(
    text: str,
    *,
    project: str | None = None,
    source: str = "manual",
    filing_mode: str = "auto",
    store: SkratchedStore,
) -> dict[str, Any]:
    """Persist a decision, workaround, or root cause worth remembering across sessions."""
    if not text.strip():
        raise ValueError("text is required")
    return store.capture(
        text,
        source=source or "manual",
        project=project or None,
        filing_mode=filing_mode or "auto",
    )


def parse_allowed_roots(raw: str | None) -> list[Path]:
    """Parse an os.pathsep-delimited allowlist of workspace scan roots."""
    if not raw or not raw.strip():
        return []
    return [
        Path(entry).expanduser().resolve(strict=False)
        for entry in raw.split(os.pathsep)
        if entry.strip()
    ]


def _is_within_allowed_roots(candidate: Path, allowed_roots: list[Path]) -> bool:
    resolved = candidate.resolve(strict=True)
    for allowed in allowed_roots:
        try:
            resolved.relative_to(allowed)
            return True
        except ValueError:
            continue
    return False


def skratched_workspace_scan(
    root: str,
    *,
    project: str | None = None,
    preset: str | None = None,
    max_age_days: int | None = None,
    store: SkratchedStore,
    allowed_roots: list[Path],
) -> dict[str, Any]:
    """Trigger a metadata-only Workspace Scout preview scan of a pre-approved root.

    Roots must resolve under one of SKRATCHED_MCP_ALLOWED_ROOTS. Returns
    metadata previews only -- never file content -- and never captures.
    """
    candidate = Path(root).expanduser()
    if not _is_within_allowed_roots(candidate, allowed_roots):
        raise ValueError(
            f"root is not within {ALLOWED_ROOTS_ENV}: configure this env var "
            "with the workspace roots an agent may scan before calling this tool"
        )
    since = None
    if max_age_days is not None:
        since = f"{int(max_age_days)}d"
    return store.workspace_scan_preview(
        root,
        project=project or None,
        type_filter=preset or "all",
        since=since,
    )


def confirm_reveal(item_id: str, reason: str) -> bool:
    """Block on a stdin TTY prompt before allowing a secret reveal.

    Returns False (never raises) for every non-affirmative path: no
    attached TTY, blank/garbage input, EOF, or interrupt. Only an explicit
    y/yes answer on a real terminal returns True.
    """
    if not sys.stdin.isatty():
        return False

    prompt = (
        f"\n[skratched] An agent is requesting to reveal item {item_id} ({reason}).\n"
        "Allow this one-time reveal? [y/N]: "
    )
    try:
        answer = input(prompt)
    except (EOFError, KeyboardInterrupt):
        return False

    return answer.strip().lower() in {"y", "yes"}


def skratched_reveal(
    item_id: str,
    reason: str,
    *,
    store: SkratchedStore,
    confirm: Callable[[str, str], bool] = confirm_reveal,
) -> dict[str, Any]:
    """Reveal a real secret value, gated on a synchronous human confirmation.

    Never returns the real value without an explicit confirmed=True from the
    confirm hook (a blocking stdin TTY prompt by default). A decline, missing
    TTY, or unknown item all return {"confirmed": False} with no real value
    and no leaked shape/length hints beyond what /api/reveal already exposes.
    """
    try:
        store.get_item(item_id)
    except KeyError as exc:
        raise ValueError(f"unknown item_id: {item_id}") from exc

    confirmed = bool(confirm(item_id, reason))
    try:
        item = store.reveal_item(item_id, local_unlock=confirmed, reason=reason)
    except PermissionError:
        return {"confirmed": False}
    return {"confirmed": True, "item": item}


def build_app(*, store: SkratchedStore, allowed_roots: list[Path]):
    """Construct the FastMCP app and register all 6 Skratched tools against store."""
    from mcp.server.fastmcp import FastMCP

    app = FastMCP(name="skratched")

    @app.tool()
    def skratched_health_tool() -> dict[str, Any]:
        """Check whether the local Skratched store is reachable and healthy."""
        return skratched_health(store=store)

    @app.tool()
    def skratched_search_tool(query: str, limit: int = 10) -> dict[str, Any]:
        """Search redacted Skratched memory before assuming something hasn't been solved before."""
        return skratched_search(query, limit=limit, store=store)

    @app.tool()
    def skratched_context_tool(item_id: str) -> dict[str, Any]:
        """Get associated links/duplicates/neighbors for a Skratched search result item."""
        return skratched_context(item_id, store=store)

    @app.tool()
    def skratched_capture_tool(
        text: str,
        project: str | None = None,
        source: str = "agent",
        filing_mode: str = "auto",
    ) -> dict[str, Any]:
        """Persist a decision, workaround, or root cause worth remembering across sessions."""
        return skratched_capture(
            text, project=project, source=source, filing_mode=filing_mode, store=store
        )

    @app.tool()
    def skratched_workspace_scan_tool(
        root: str,
        project: str | None = None,
        preset: str | None = None,
        max_age_days: int | None = None,
    ) -> dict[str, Any]:
        """Scan a pre-approved local root (see SKRATCHED_MCP_ALLOWED_ROOTS) for metadata-only candidates."""
        return skratched_workspace_scan(
            root,
            project=project,
            preset=preset,
            max_age_days=max_age_days,
            store=store,
            allowed_roots=allowed_roots,
        )

    @app.tool()
    def skratched_reveal_tool(item_id: str, reason: str) -> dict[str, Any]:
        """Reveal a real secret value. Blocks on a human y/N prompt in the server's terminal."""
        return skratched_reveal(item_id, reason, store=store)

    return app


def main() -> None:
    from .config import load_config

    config = load_config()
    store = SkratchedStore(config.db_path)
    allowed_roots = parse_allowed_roots(os.environ.get(ALLOWED_ROOTS_ENV))
    app = build_app(store=store, allowed_roots=allowed_roots)
    app.run(transport="stdio")


if __name__ == "__main__":
    main()
