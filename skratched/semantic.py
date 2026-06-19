from __future__ import annotations

import json
import math
import re
from typing import Any


STOP_WORDS = {
    "a",
    "an",
    "and",
    "are",
    "for",
    "from",
    "in",
    "last",
    "my",
    "of",
    "or",
    "the",
    "to",
    "was",
    "were",
    "with",
}

SEMANTIC_GROUPS = [
    {
        "name": "credentials",
        "terms": {
            "api",
            "apikey",
            "credential",
            "credentials",
            "key",
            "keys",
            "password",
            "secret",
            "secrets",
            "token",
            "tokens",
        },
    },
    {
        "name": "openrouter",
        "terms": {
            "gateway",
            "llm",
            "model",
            "openrouter",
            "provider",
            "providers",
            "router",
            "routing",
            "vendor",
            "vendors",
        },
    },
    {
        "name": "sql",
        "terms": {
            "database",
            "from",
            "join",
            "query",
            "select",
            "sql",
            "table",
            "users",
            "where",
        },
    },
    {
        "name": "prompts",
        "terms": {
            "assistant",
            "instruction",
            "instructions",
            "prompt",
            "prompts",
            "system",
            "user",
        },
    },
    {
        "name": "screenshots",
        "terms": {
            "capture",
            "image",
            "photo",
            "screen",
            "screenshot",
            "screenshots",
            "shot",
        },
    },
    {
        "name": "commands",
        "terms": {
            "cli",
            "command",
            "commands",
            "curl",
            "git",
            "shell",
            "terminal",
        },
    },
]


def tokenize(value: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", value.lower())


def local_semantic_signal(query: str, item_text: str, *, category: str, facets: dict[str, Any]) -> dict[str, Any]:
    query_terms = {term for term in tokenize(query) if term not in STOP_WORDS and len(term) > 1}
    item_terms = set(tokenize(item_text))
    item_terms.update(tokenize(category))
    item_terms.update(tokenize(json.dumps(facets, sort_keys=True)))

    expanded_terms = set(query_terms)
    active_groups: list[str] = []
    matched_groups: list[str] = []
    for group in SEMANTIC_GROUPS:
        terms = set(group["terms"])
        if query_terms & terms:
            active_groups.append(group["name"])
            expanded_terms.update(terms)
            if item_terms & terms:
                matched_groups.append(group["name"])

    bridge_terms = expanded_terms - query_terms
    matched_bridge_terms = sorted(bridge_terms & item_terms)
    matched_query_terms = sorted(query_terms & item_terms)
    raw_score = (len(matched_bridge_terms) * 0.75) + (len(matched_groups) * 0.5)
    normalizer = math.sqrt(max(len(query_terms), 1))
    score = round(raw_score / normalizer, 3)

    return {
        "score": score,
        "active_groups": active_groups,
        "matched_groups": matched_groups,
        "matched_terms": matched_bridge_terms[:8],
        "exact_terms": matched_query_terms[:8],
    }
