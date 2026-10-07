"""Machine-readable JSON report -- a straight serialization of AuditReport,
independent of the audit engine and of the other report formats."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from enum import Enum
from pathlib import Path

from engine.result_model import AuditReport


def _default(obj):
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def generate(report: AuditReport, output_path: str | Path) -> None:
    payload = asdict(report)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=_default)
