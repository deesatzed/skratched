from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit


OPENROUTER_KEY_RE = re.compile(r"\bsk-or-v1-[A-Za-z0-9_-]{24,}\b")
GENERIC_SECRET_RE = re.compile(
    r"(?i)\b([A-Za-z0-9_./-]*(?:api[_-]?key|secret|token|password|passwd|pwd)[A-Za-z0-9_./-]*)"
    r"\s*=\s*(?!<[^>\s]+>)(['\"]?)[A-Za-z0-9_./+=:@-]{8,}\2"
)
STRUCTURED_SECRET_RE = re.compile(
    r"(?i)\b((?:['\"]?[A-Za-z0-9_./-]*(?:api[_-]?key|api-key|secret|token|password|passwd|pwd)"
    r"[A-Za-z0-9_./-]*['\"]?)\s*:\s*)(?!<[^>\s]+>)(['\"]?)[A-Za-z0-9_./+=:@-]{8,}\2"
)
URL_CREDENTIAL_RE = re.compile(
    r"(?i)\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis)://)([^/\s:@]+):([^@\s/]+)@"
)
BEARER_TOKEN_RE = re.compile(
    r"(?i)\b(authorization\s*:\s*bearer\s+)(?!<[^>\s]+>)[A-Za-z0-9._~+/=-]{12,}"
)
PASSWORD_FLAG_RE = re.compile(
    r"(?i)(--(?:password|pass|pwd)(?:=|\s+))(?!<[^>\s]+>)[^\s'\"]{6,}"
)
URL_RE = re.compile(r"https?://[^\s<>'\"\\)\]\}]+")
SQL_RE = re.compile(r"(?is)\b(select|insert|update|delete|with|create|alter|drop)\b.+\b(from|into|table|where|values)\b")
SQL_OPERATION_RE = re.compile(r"(?i)\b(select|insert|update|delete|with|create|alter|drop)\b")
SQL_TABLE_RE = re.compile(
    r"(?i)\b(?:from|join|into|update|table)\s+([A-Za-z_][A-Za-z0-9_.$-]*)"
)
SQL_SKIP_TABLE_NAMES = {"select", "where", "values", "set", "on", "using", "if", "exists"}
PY_SYMBOL_RE = re.compile(r"(?m)^\s*(?:async\s+)?(?:def|class)\s+([A-Za-z_][A-Za-z0-9_]*)")
JS_FUNCTION_RE = re.compile(r"(?m)^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(")
JS_CONST_FN_RE = re.compile(
    r"(?ms)^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)"
    r"\s*(?::[^=\n]+)?=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][A-Za-z0-9_$]*)"
    r"\s*(?::\s*[^=\n]+?)?\s*=>"
)


def utc_now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _reference_id(value: str) -> str:
    return f"ref_{hashlib.sha256(value.encode('utf-8')).hexdigest()[:16]}"


def redact_text(text: str) -> str:
    text = OPENROUTER_KEY_RE.sub("[REDACTED:openrouter_key]", text)
    text = URL_CREDENTIAL_RE.sub(r"\1[REDACTED:credentials]@", text)
    text = BEARER_TOKEN_RE.sub(r"\1[REDACTED:bearer_token]", text)
    text = PASSWORD_FLAG_RE.sub(r"\1[REDACTED:secret]", text)

    def redact_structured(match: re.Match[str]) -> str:
        prefix = match.group(1)
        quote = match.group(2)
        return f"{prefix}{quote}[REDACTED:secret]{quote}"

    text = STRUCTURED_SECRET_RE.sub(redact_structured, text)

    def redact_generic(match: re.Match[str]) -> str:
        key = match.group(1)
        return f"{key}=[REDACTED:secret]"

    return GENERIC_SECRET_RE.sub(redact_generic, text)


def has_secret_signal(text: str) -> bool:
    return redact_text(text) != text


def extract_references(text: str) -> list[dict[str, str]]:
    references: list[dict[str, str]] = []
    seen: set[str] = set()
    for match in URL_RE.finditer(text):
        raw_url = match.group(0).rstrip(".,;:")
        redacted_url = redact_text(raw_url)
        parsed = urlsplit(redacted_url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            continue
        netloc = parsed.netloc.lower()
        normalized = urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "", parsed.query or "", ""))
        if normalized in seen:
            continue
        seen.add(normalized)
        references.append(
            {
                "id": _reference_id(normalized),
                "kind": "url",
                "url": normalized,
                "host": (parsed.hostname or netloc).lower(),
            }
        )
    return references


def classify_risk(text: str, *, category: str, sensitivity: str) -> dict[str, Any]:
    lowered = text.lower()
    reasons: list[str] = []
    risk_class = "safe"
    if sensitivity == "sensitive":
        risk_class = "sensitive"
        reasons.append("contains secret-like material")
    if re.search(r"(?is)\b(drop|delete|truncate|alter)\b.+\b(table|from|database)\b", text):
        if risk_class == "safe":
            risk_class = "caution"
        reasons.append("mutating SQL operation")
    elif category == "SQL queries":
        if risk_class == "safe":
            risk_class = "caution"
        reasons.append("database query requires review")
    if category == "commands":
        if risk_class == "safe":
            risk_class = "caution"
        reasons.append("shell command requires review")
    if re.search(r"(?m)\brm\s+-[A-Za-z]*r[A-Za-z]*f|\brm\s+-[A-Za-z]*f[A-Za-z]*r", text) and re.search(
        r"(?m)(?:^|\s)/(?:\s|$)|--no-preserve-root", text
    ):
        risk_class = "blocked"
        reasons.append("destructive filesystem command")
    if not reasons:
        reasons.append("no sensitive or destructive signals")
    return {"risk_class": risk_class, "risk_reasons": sorted(set(reasons))}


def chunk_manifest(chunks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    manifest: list[dict[str, Any]] = []
    for chunk in chunks:
        start = int(chunk["start"])
        end = int(chunk["end"])
        manifest.append(
            {
                "index": int(chunk["index"]),
                "start": start,
                "end": end,
                "length": end - start,
                "overlap_before": int(chunk.get("overlap_before") or 0),
                "hash": str(chunk["hash"]),
            }
        )
    return manifest


def chunk_text(text: str, chunk_size: int = 4000, overlap: int = 400) -> list[dict[str, Any]]:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    if overlap < 0 or overlap >= chunk_size:
        raise ValueError("overlap must be >= 0 and smaller than chunk_size")
    if not text:
        return []

    chunks: list[dict[str, Any]] = []
    start = 0
    index = 0
    while start < len(text):
        end = min(len(text), start + chunk_size)
        chunks.append(
            {
                "index": index,
                "start": start,
                "end": end,
                "overlap_before": 0 if index == 0 else overlap,
                "text": text[start:end],
                "hash": content_hash(text[start:end]),
            }
        )
        if end == len(text):
            break
        start = end - overlap
        index += 1
    return chunks


def resolve_safe_path(root: str | Path, requested: str | Path) -> Path:
    root_path = Path(root).resolve()
    candidate = (root_path / requested).resolve(strict=False)
    try:
        candidate.relative_to(root_path)
    except ValueError as exc:
        raise ValueError(f"path escapes root: {requested}") from exc
    return candidate


def split_sql_statements(text: str) -> list[str]:
    statements: list[str] = []
    current: list[str] = []
    quote: str | None = None
    previous = ""
    for char in text:
        current.append(char)
        if char in {"'", '"'} and previous != "\\":
            quote = None if quote == char else char if quote is None else quote
        if char == ";" and quote is None:
            statement = "".join(current).strip()
            if statement.strip("; \n\t"):
                statements.append(statement)
            current = []
        previous = char
    tail = "".join(current).strip()
    if tail:
        statements.append(tail)
    return statements


def normalize_sql(text: str) -> str:
    normalized = " ".join(text.strip().split()).lower()
    normalized = re.sub(r"\s*;\s*", "; ", normalized)
    normalized = re.sub(r"\s+([(),;])", r"\1", normalized)
    normalized = re.sub(r"([(),])\s*", r"\1 ", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized.rstrip("; ") + ";" if normalized else ""


def _unique_ordered(values: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            output.append(value)
    return output


def extract_sql_metadata(text: str) -> dict[str, Any]:
    statements = split_sql_statements(text)
    normalized = normalize_sql(text)
    operations: list[str] = []
    tables: list[str] = []
    for statement in statements or [text]:
        lowered = statement.strip().lower()
        if lowered.startswith("with"):
            operations.append("select")
        for match in SQL_OPERATION_RE.finditer(statement):
            operation = match.group(1).lower()
            operations.append("select" if operation == "with" else operation)
        for match in SQL_TABLE_RE.finditer(statement):
            table = match.group(1).strip('"`[]').lower()
            if table and table not in SQL_SKIP_TABLE_NAMES:
                tables.append(table.split(".")[-1])
    operations = _unique_ordered(operations)
    ordered_tables = _unique_ordered(tables)
    tables = sorted(ordered_tables)
    signal_count = len(statements) + len(tables)
    if re.search(r"(?i)\b(join|with|group\s+by|window|over\s*\(|union)\b", text):
        signal_count += 2
    if re.search(r"(?i)\b(insert|update|delete|drop|alter)\b", text):
        signal_count += 1
    if signal_count >= 6:
        complexity = "complex"
    elif signal_count >= 3:
        complexity = "moderate"
    else:
        complexity = "simple"
    title_op = operations[0].upper() if operations else "SQL"
    title_order = list(tables)
    if title_op == "SELECT":
        from_matches = [match.group(1).strip('"`[]').lower().split(".")[-1] for match in re.finditer(r"(?i)\bfrom\s+([A-Za-z_][A-Za-z0-9_.$-]*)", text)]
        if from_matches:
            primary = from_matches[-1]
            title_order = [primary] + [table for table in tables if table != primary]
    elif title_op in {"INSERT", "UPDATE", "DELETE"} and ordered_tables:
        primary = ordered_tables[0]
        title_order = [primary] + [table for table in tables if table != primary]
    title_tables = ", ".join(title_order[:3]) if title_order else "statement"
    return {
        "sql_statement_count": len(statements) or 1,
        "sql_operations": operations,
        "sql_tables": tables,
        "sql_complexity": complexity,
        "sql_normalized": normalized,
        "sql_title": f"{title_op} {title_tables}",
    }


def detect_code_language(text: str, filename: str | None = None) -> str:
    suffix = Path(filename or "").suffix.lower()
    if suffix == ".py":
        return "python"
    if suffix in {".ts", ".tsx"}:
        return "typescript"
    if suffix in {".js", ".jsx"}:
        return "javascript"
    if suffix in {".sh", ".zsh", ".bash"}:
        return "shell"
    if re.search(r"(?m)^\s*(import\s+.+\s+from|export\s+|const\s+\w+\s*=|let\s+\w+\s*=|function\s+\w+)", text):
        return "typescript" if suffix in {".ts", ".tsx"} else "javascript"
    if re.search(r"(?m)^\s*(from\s+\S+\s+import|import\s+[A-Za-z_][A-Za-z0-9_.]*(?:\s+as\s+\w+)?\s*$|def\s+\w+|class\s+\w+)", text):
        return "python"
    if re.search(r"(?m)^\s*(#!/bin/(?:ba|z)?sh|set\s+-[a-zA-Z]+|[A-Za-z_][A-Za-z0-9_]*=|(?:if|for|while)\s+.+;\s*then)", text):
        return "shell"
    return "unknown"


def extract_code_metadata(text: str, *, filename: str | None = None) -> dict[str, Any]:
    language = detect_code_language(text, filename=filename)
    imports: list[str] = []
    symbols: list[str] = []
    tags = ["code"]

    if language == "python":
        symbols = PY_SYMBOL_RE.findall(text)
        for match in re.finditer(r"(?m)^\s*import\s+([A-Za-z_][A-Za-z0-9_.]*)", text):
            imports.append(match.group(1))
        for match in re.finditer(r"(?m)^\s*from\s+([A-Za-z_][A-Za-z0-9_.]*)\s+import\s+([A-Za-z_][A-Za-z0-9_.*]*)", text):
            module, name = match.groups()
            imports.append(f"{module}.{name}" if name != "*" else module)
        if "class " in text:
            tags.append("class")
        if re.search(r"(?m)^\s*(?:async\s+)?def\s+", text):
            tags.append("function")
    elif language in {"javascript", "typescript"}:
        symbol_matches: list[tuple[int, str]] = []
        symbol_matches.extend((match.start(), match.group(1)) for match in JS_FUNCTION_RE.finditer(text))
        symbol_matches.extend((match.start(), match.group(1)) for match in JS_CONST_FN_RE.finditer(text))
        symbols = [name for _, name in sorted(symbol_matches)]
        for match in re.finditer(r"""(?m)^\s*import\s+.+?\s+from\s+['"]([^'"]+)['"]""", text):
            imports.append(match.group(1))
        for match in re.finditer(r"""(?m)^\s*(?:const|let|var)\s+\{?\s*([A-Za-z_$][A-Za-z0-9_$]*)""", text):
            name = match.group(1)
            if name not in symbols and "=>" in text[match.end() : match.end() + 80]:
                symbols.append(name)
        tags.append(language)
        if "function" in text or "=>" in text:
            tags.append("function")
    elif language == "shell":
        for match in re.finditer(r"(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\)\s*\{", text):
            symbols.append(match.group(1))
        for command in re.findall(r"(?m)^\s*([a-z][a-z0-9_.-]+)\s+", text.lower()):
            if command not in {"if", "then", "fi", "for", "do", "done", "while"}:
                imports.append(command)
        tags.append("shell")

    imports = _unique_ordered(imports)
    symbols = _unique_ordered(symbols)
    branch_count = len(re.findall(r"(?i)\b(if|elif|else|for|while|case|catch|except|switch)\b", text))
    line_count = len([line for line in text.splitlines() if line.strip()])
    if branch_count >= 4 or line_count >= 80:
        complexity = "complex"
    elif branch_count >= 1 or line_count >= 8:
        complexity = "moderate"
    else:
        complexity = "simple"
    title_bits = symbols[:3] or imports[:2] or [language]
    return {
        "code_language": language,
        "code_symbols": symbols,
        "code_imports": imports,
        "code_complexity": complexity,
        "code_title": f"{language}: {', '.join(title_bits)}",
        "code_line_count": line_count,
        "code_branch_count": branch_count,
        "code_tags": sorted(set(tags + ([language] if language != "unknown" else []))),
    }


def analyze_capture(text: str, *, source: str = "manual", filename: str | None = None) -> dict[str, Any]:
    redacted = redact_text(text)
    lowered = text.lower()
    code_language_hint = detect_code_language(text, filename=filename)
    filename_suffix = Path(filename or "").suffix.lower()
    vendors: list[str] = []
    tags: list[str] = []
    category = "notes"
    sensitivity = "safe"

    secret_signal = has_secret_signal(text)

    if OPENROUTER_KEY_RE.search(text) or "openrouter_api_key" in lowered:
        category = "API-Keys"
        sensitivity = "sensitive"
        vendors.append("openrouter")
        tags.extend(["api-key", "secret", "openrouter"])
    elif secret_signal:
        category = "API-Keys"
        sensitivity = "sensitive"
        tags.extend(["secret", "credential"])
        if re.search(r"(?i)\b(postgres(?:ql)?|mysql|mariadb|mongodb|redis)://", text):
            vendors.append("database")
    elif SQL_RE.search(text):
        category = "SQL queries"
        tags.extend(["sql", "query"])
    elif source.startswith("screenshot") or (filename and "screenshot" in filename.lower()):
        category = "screenshots-work"
        tags.append("screenshot")
    elif "prompt" in lowered or text.strip().lower().startswith(("system:", "user:", "assistant:")):
        category = "prompts"
        tags.append("prompt")
    elif (
        code_language_hint in {"python", "javascript", "typescript"}
        or (
            code_language_hint == "shell"
            and (
                filename_suffix in {".sh", ".zsh", ".bash"}
                or re.search(r"(?m)^\s*(#!/bin/|[A-Za-z_][A-Za-z0-9_]*\s*\(\)\s*\{|(?:if|for|while)\s+.+;\s*then)", text)
            )
        )
        or re.search(r"(?m)^\s*(def |class |function |const |let |var |import |from )", text)
    ):
        category = "code"
        tags.append("code")
    elif re.search(r"(?m)^\s*(git|npm|python|uv|curl|psql)\s+", text.strip()):
        category = "commands"
        tags.append("command")
    if re.search(r"(?m)\brm\s+-[A-Za-z]*r[A-Za-z]*f|\brm\s+-[A-Za-z]*f[A-Za-z]*r", text) and re.search(
        r"(?m)(?:^|\s)/(?:\s|$)|--no-preserve-root", text
    ):
        category = "commands"
        tags.append("command")

    preview = redacted[:500]
    chunks = chunk_text(text, chunk_size=4000, overlap=400)
    summary = " ".join(redacted.split())[:180]
    references = extract_references(text)
    risk = classify_risk(text, category=category, sensitivity=sensitivity)

    facets: dict[str, Any] = {
        "source": source,
        "vendors": vendors,
        "tags": sorted(set(tags)),
        "filename": filename,
        "length": len(text),
        "chunk_count": len(chunks),
        "risk_class": risk["risk_class"],
        "risk_reasons": risk["risk_reasons"],
    }
    if references:
        facets["references"] = references
        facets["reference_ids"] = [reference["id"] for reference in references]
        facets["reference_hosts"] = sorted({reference["host"] for reference in references})
    if category == "SQL queries":
        sql_metadata = extract_sql_metadata(text)
        facets.update(sql_metadata)
        tags.extend(sql_metadata["sql_operations"])
        if "join" in lowered:
            tags.append("join")
        facets["tags"] = sorted(set(tags))
    elif category == "code":
        code_metadata = extract_code_metadata(text, filename=filename)
        facets.update({key: value for key, value in code_metadata.items() if key != "code_tags"})
        tags.extend(code_metadata["code_tags"])
        facets["tags"] = sorted(set(tags))

    return {
        "category": category,
        "sensitivity": sensitivity,
        "preview": preview,
        "summary": summary,
        "content_hash": content_hash(text),
        "facets": facets,
        "chunks": chunk_manifest(chunks),
    }
