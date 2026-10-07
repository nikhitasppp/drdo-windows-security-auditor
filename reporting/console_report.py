"""Human-readable console summary. Independent of the audit engine: it only
consumes the finished AuditReport, never re-derives status/scoring itself."""

from __future__ import annotations

from engine.result_model import AuditReport, CheckStatus

_STATUS_ORDER = [CheckStatus.FAIL, CheckStatus.WARNING, CheckStatus.UNABLE_TO_COLLECT]


def generate(report: AuditReport) -> str:
    lines: list[str] = []
    w = lines.append

    w("=" * 78)
    w("WINDOWS 11 SYSTEM AUDIT REPORT")
    w("=" * 78)
    w(f"Host:           {report.host_name}")
    w(f"Generated:      {report.generated_at.isoformat(timespec='seconds')}")
    w(f"Administrator:  {'Yes' if report.is_admin else 'No (some checks were skipped or limited)'}")
    w("")

    scoring = report.scoring or {}
    counts = scoring.get("counts", {})
    w("-" * 78)
    w("OVERALL RESULT")
    w("-" * 78)
    w(f"  Compliance:   {_fmt_pct(scoring.get('compliance_percent'))}")
    w(f"  Risk score:   {_fmt_pct(scoring.get('risk_score'))}  (higher = worse)")
    w(f"  Coverage:     {_fmt_pct(scoring.get('coverage_percent'))}  (share of enabled checks actually evaluated)")
    w("")
    w(f"  Total checks: {counts.get('total_checks', 0)}")
    w(f"    PASS               : {counts.get('passed', 0)}")
    w(f"    FAIL               : {counts.get('failed', 0)}")
    w(f"    WARNING            : {counts.get('warnings', 0)}")
    w(f"    NOT_APPLICABLE     : {counts.get('not_applicable', 0)}")
    w(f"    UNABLE_TO_COLLECT  : {counts.get('unable_to_collect', 0)}")
    w("")

    w("-" * 78)
    w("CATEGORY BREAKDOWN")
    w("-" * 78)
    for category, cat_score in sorted(scoring.get("by_category", {}).items()):
        w(f"  {category:<38} compliance {_fmt_pct(cat_score.get('compliance_percent')):>7}"
          f"   coverage {_fmt_pct(cat_score.get('coverage_percent')):>7}")
    w("")

    for status in _STATUS_ORDER:
        matching = [r for r in report.results if r.status == status]
        if not matching:
            continue
        w("-" * 78)
        w(f"{status.value} ({len(matching)})")
        w("-" * 78)
        for r in sorted(matching, key=lambda x: x.audit_id):
            w(f"  [{r.severity.value:<8}] {r.audit_id}  {r.category} / {r.parameter}")
            w(f"             expected: {r.expected}    actual: {r.actual!r}")
            if r.detail:
                w(f"             detail:   {r.detail}")
            w(f"             remediation: {r.remediation}")
        w("")

    w("=" * 78)
    return "\n".join(lines)


def _fmt_pct(value) -> str:
    return "N/A" if value is None else f"{value}%"
