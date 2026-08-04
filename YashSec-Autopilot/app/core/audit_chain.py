from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

AUDIT_EVENT_FIELDS = (
    "timestamp",
    "user_id",
    "username",
    "action",
    "resource_type",
    "resource_id",
    "result",
    "purpose",
    "correlation_id",
    "ip_address",
    "user_agent",
    "details",
)


def canonical_event(source: Mapping[str, Any]) -> dict[str, Any]:
    return {field: source.get(field) for field in AUDIT_EVENT_FIELDS}


def event_hash(event: Mapping[str, Any], previous_hash: str) -> str:
    canonical = json.dumps(
        canonical_event(event),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )
    return hashlib.sha256((previous_hash + canonical).encode("utf-8")).hexdigest()
