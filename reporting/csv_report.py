"""CSV report: one row per check result, for spreadsheet review. Independent
of the audit engine and of the other report formats."""

from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path

import branding
from engine.result_model import AuditReport

_FIELDS = [
    "audit_id", "category", "subcategory", "parameter", "description",
    "data_source", "collection_method", "expected", "actual", "status",
    "severity", "remediation", "detail",
]


def generate(report: AuditReport, output_path: str | Path) -> None:
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        _write_metadata_block(f, report)
        writer = csv.DictWriter(f, fieldnames=_FIELDS)
        writer.writeheader()
        for r in sorted(report.results, key=lambda x: x.audit_id):
            writer.writerow({
                "audit_id": r.audit_id,
                "category": r.category,
                "subcategory": r.subcategory,
                "parameter": r.parameter,
                "description": r.description,
                "data_source": r.data_source,
                "collection_method": r.collection_method,
                "expected": r.expected,
                "actual": r.actual,
                "status": r.status.value,
                "severity": r.severity.value,
                "remediation": r.remediation,
                "detail": r.detail or "",
            })


def _write_metadata_block(f, report: AuditReport) -> None:
    """Prepend Application/Organization/.../Report Generated rows, only
    when the report carries GUI-supplied metadata (report.user_name is
    set) -- keeps a plain `python main.py --formats csv` CSV looking
    exactly as it did before this was added."""
    if not report.user_name:
        return

    audit_start = report.audit_start or report.generated_at
    audit_end = report.audit_end or report.generated_at
    writer = csv.writer(f)
    rows = [
        ("Application", branding.APP_NAME),
        ("Organization", branding.ORGANIZATION),
        ("Location", branding.LOCATION),
        ("Ministry", branding.MINISTRY),
        ("System Name", report.host_name),
        ("User", report.user_name),
        ("Lab", report.lab or ""),
    ]
    if report.remarks:
        rows.append(("Remarks", report.remarks))
    rows += [
        ("Audit Start", audit_start.strftime("%Y-%m-%d %H:%M:%S")),
        ("Audit End", audit_end.strftime("%Y-%m-%d %H:%M:%S")),
        ("Report Generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    ]
    for label, value in rows:
        writer.writerow([label, value])
    writer.writerow([])
