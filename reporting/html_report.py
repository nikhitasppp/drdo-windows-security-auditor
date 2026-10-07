"""
Self-contained HTML report -- independent of the audit engine and of the
other report formats; it only consumes the finished AuditReport. No
external assets (fonts, scripts, stylesheets) are loaded, consistent with
this tool's offline requirement.
"""

from __future__ import annotations

import base64
from datetime import datetime
from html import escape
from pathlib import Path

import branding
from engine.result_model import AuditReport, CheckResult, CheckStatus, Severity

_STATUS_COLORS = {
    "PASS": "#1a7f37",
    "FAIL": "#cf222e",
    "WARNING": "#9a6700",
    "NOT_APPLICABLE": "#57606a",
    "UNABLE_TO_COLLECT": "#6639ba",
}
_SEVERITY_COLORS = {
    "CRITICAL": "#8e1600",
    "HIGH": "#cf222e",
    "MEDIUM": "#9a6700",
    "LOW": "#4b6a00",
    "INFO": "#57606a",
}


def generate(report: AuditReport, output_path: str | Path) -> None:
    html_text = _render(report)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_text)


def _render(report: AuditReport) -> str:
    scoring = report.scoring or {}
    counts = scoring.get("counts", {})

    scored_results = [r for r in report.results if r.severity != Severity.INFO]
    failed = sorted([r for r in scored_results if r.status == CheckStatus.FAIL], key=_severity_sort_key)
    warnings = sorted([r for r in scored_results if r.status == CheckStatus.WARNING], key=_severity_sort_key)
    passed = sorted([r for r in report.results if r.status == CheckStatus.PASS], key=lambda r: r.audit_id)
    unable = sorted([r for r in report.results if r.status == CheckStatus.UNABLE_TO_COLLECT], key=lambda r: r.audit_id)
    not_applicable = sorted([r for r in report.results if r.status == CheckStatus.NOT_APPLICABLE], key=lambda r: r.audit_id)
    critical = [r for r in failed if r.severity == Severity.CRITICAL]

    return f"""<title>Windows 11 System Audit Report</title>
<style>
{_CSS}
</style>
<div class="page">

  {_brand_banner()}

  <header>
    <h1>Windows 11 System Audit Report</h1>
    <p class="subtitle">Automated Security &amp; Compliance Audit</p>
  </header>

  <section class="card">
    <h2>Audit Information</h2>
    {_audit_info_table(report)}
  </section>

  <section class="card">
    <h2>1. Executive Summary</h2>
    <p>
      This report presents the results of an automated, read-only security and
      configuration audit of <strong>{escape(report.host_name)}</strong>, executed on
      {report.generated_at.strftime('%d %B %Y at %H:%M:%S')}.
      {len(report.results)} checks were defined across
      {len(scoring.get('by_category', {}))} categories;
      {counts.get('passed', 0)} passed, {counts.get('failed', 0)} failed,
      {counts.get('warnings', 0)} produced advisory warnings,
      {counts.get('not_applicable', 0)} did not apply to this system, and
      {counts.get('unable_to_collect', 0)} could not be verified{'' if report.is_admin else ' (this run was not elevated; re-run as Administrator for full coverage)'}.
    </p>
    {_critical_banner(critical)}
  </section>

  <section class="card">
    <h2>2. System Information</h2>
    {_system_info_table(report)}
  </section>

  <section class="card">
    <h2>3. Overall Security / Compliance Score</h2>
    {_score_cards(scoring)}
  </section>

  <section class="card">
    <h2>4. Category-wise Results</h2>
    {_category_table(scoring)}
  </section>

  <section class="card">
    <h2>5. Failed Checks ({len(failed)})</h2>
    {_findings_table(failed) if failed else '<p class="muted">No failed checks.</p>'}
  </section>

  <section class="card">
    <h2>6. Warning Checks ({len(warnings)})</h2>
    {_findings_table(warnings) if warnings else '<p class="muted">No warning checks.</p>'}
  </section>

  <section class="card">
    <h2>7. Passed Checks ({len(passed)})</h2>
    <details>
      <summary>Show {len(passed)} passed checks</summary>
      {_findings_table(passed, compact=True) if passed else '<p class="muted">None.</p>'}
    </details>
  </section>

  <section class="card">
    <h2>8. Critical Findings ({len(critical)})</h2>
    {_findings_table(critical) if critical else '<p class="muted">No critical-severity failures.</p>'}
  </section>

  <section class="card">
    <h2>9. Recommended Remediation</h2>
    {_remediation_list(failed + warnings)}
  </section>

  <section class="card">
    <h2>10&ndash;12. Audit Metadata</h2>
    <table class="kv">
      <tr><th>Audit timestamp</th><td>{report.generated_at.isoformat(timespec='seconds')}</td></tr>
      <tr><th>Host name</th><td>{escape(report.host_name)}</td></tr>
      <tr><th>Operating system</th><td>{escape(str(report.os_info.get('os_caption', 'Unknown')))} (Build {escape(str(report.os_info.get('os_build', '?')))})</td></tr>
      <tr><th>Running as Administrator</th><td>{'Yes' if report.is_admin else 'No'}</td></tr>
    </table>
    {'<p class="notice">This audit ran without administrator privileges. Checks that require elevation (BitLocker, local security policy, audit policy, Security event log, TPM, Secure Boot) are reported as UNABLE_TO_COLLECT below rather than assumed. Re-run as Administrator for full coverage.</p>' if not report.is_admin else ''}
  </section>

  <section class="card">
    <h2>13. Checks That Could Not Be Collected ({len(unable)})</h2>
    {_findings_table(unable, show_detail=True) if unable else '<p class="muted">All enabled checks were successfully evaluated.</p>'}
  </section>

  <section class="card">
    <h2>14. Checks Not Applicable ({len(not_applicable)})</h2>
    <p class="muted">Checks that were correctly skipped because their prerequisite didn't hold on this system (e.g. a Bluetooth check when no Bluetooth adapter is present) -- distinct from checks that failed to collect. Excluded from the compliance/risk denominator; see Section 3.</p>
    {_findings_table(not_applicable, show_detail=True) if not_applicable else '<p class="muted">No checks were not applicable on this system.</p>'}
  </section>

  <footer>
    Generated by the Windows 11 System Auditing Framework. Read-only; no system
    configuration was modified while producing this report.
  </footer>

</div>

<script>
  window.addEventListener('beforeprint', function () {{
    document.querySelectorAll('details').forEach(function (d) {{ d.open = true; }});
  }});
</script>
"""


def _logo_data_uri() -> str:
    """Base64-inline the local DRDO logo so the HTML stays a single,
    fully offline file -- no external image reference to break if the
    file is moved or opened on another machine."""
    logo_path = branding.get_logo_path()
    if logo_path is None:
        return ""
    data = base64.b64encode(logo_path.read_bytes()).decode("ascii")
    return f"data:image/png;base64,{data}"


def _brand_banner() -> str:
    logo_uri = _logo_data_uri()
    logo_html = f'<img src="{logo_uri}" alt="DRDO" class="brand-logo">' if logo_uri else ""
    return f"""
  <div class="brand-banner">
    {logo_html}
    <div class="brand-text">
      <div class="brand-app">{escape(branding.APP_NAME)}</div>
      <div class="brand-org">{escape(branding.ORGANIZATION)} &middot; {escape(branding.MINISTRY)} &middot; {escape(branding.LOCATION)}</div>
    </div>
  </div>"""


def _audit_info_table(report: AuditReport) -> str:
    audit_start = report.audit_start or report.generated_at
    audit_end = report.audit_end or report.generated_at
    rows = [
        ("Application", branding.APP_NAME),
        ("Organization", branding.ORGANIZATION),
        ("Location", branding.LOCATION),
        ("Ministry", branding.MINISTRY),
        ("System Name", report.host_name),
        ("User", report.user_name or "Not specified"),
        ("Lab", report.lab or "Not specified"),
    ]
    if report.remarks:
        rows.append(("Remarks", report.remarks))
    rows += [
        ("Audit Start", audit_start.strftime("%Y-%m-%d %H:%M:%S")),
        ("Audit End", audit_end.strftime("%Y-%m-%d %H:%M:%S")),
        ("Report Generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    ]
    body = "".join(f"<tr><th>{escape(k)}</th><td>{escape(str(v))}</td></tr>" for k, v in rows)
    return f'<table class="kv">{body}</table>'


def _severity_sort_key(r: CheckResult):
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    return (order.get(r.severity.value, 9), r.audit_id)


def _critical_banner(critical: list[CheckResult]) -> str:
    if not critical:
        return '<p class="banner banner-ok">No critical-severity findings.</p>'
    return (
        f'<p class="banner banner-critical">{len(critical)} CRITICAL finding'
        f'{"s" if len(critical) != 1 else ""} require immediate attention '
        f'(see Section 8).</p>'
    )


def _system_info_table(report: AuditReport) -> str:
    os_info = report.os_info or {}
    rows = [
        ("Operating System", os_info.get("os_caption")),
        ("Version / Build", f"{os_info.get('os_version', '')} (Build {os_info.get('os_build', '?')})"),
        ("Architecture", os_info.get("architecture")),
        ("Computer Name", os_info.get("computer_name")),
        ("Domain / Workgroup", os_info.get("domain_or_workgroup")),
        ("CPU", os_info.get("cpu_name")),
        ("RAM (GB)", os_info.get("ram_total_gb")),
        ("Firmware Type", os_info.get("firmware_type")),
    ]
    body = "".join(
        f"<tr><th>{escape(str(k))}</th><td>{escape(str(v)) if v is not None else '<span class=\"muted\">Not collected</span>'}</td></tr>"
        for k, v in rows
    )
    return f'<table class="kv">{body}</table>'


def _score_cards(scoring: dict) -> str:
    def card(label, value, suffix=""):
        display = "N/A" if value is None else f"{value}{suffix}"
        return f'<div class="score-card"><div class="score-value">{display}</div><div class="score-label">{label}</div></div>'

    return (
        '<div class="score-row">'
        + card("Compliance", scoring.get("compliance_percent"), "%")
        + card("Risk Score", scoring.get("risk_score"), "%")
        + card("Coverage", scoring.get("coverage_percent"), "%")
        + "</div>"
    )


def _category_table(scoring: dict) -> str:
    rows = []
    for category, cat_score in sorted(scoring.get("by_category", {}).items()):
        rows.append(
            f"<tr><td>{escape(category)}</td>"
            f"<td>{_pct(cat_score.get('compliance_percent'))}</td>"
            f"<td>{_pct(cat_score.get('risk_score'))}</td>"
            f"<td>{_pct(cat_score.get('coverage_percent'))}</td></tr>"
        )
    return (
        '<table class="data"><thead><tr>'
        "<th>Category</th><th>Compliance</th><th>Risk Score</th><th>Coverage</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )


def _pct(value) -> str:
    return "N/A" if value is None else f"{value}%"


def _findings_table(results: list[CheckResult], compact: bool = False, show_detail: bool = False) -> str:
    header = "<th>ID</th><th>Category</th><th>Parameter</th><th>Severity</th><th>Status</th><th>Expected</th><th>Actual</th>"
    if not compact:
        header += "<th>Description</th><th>Remediation</th>"
    if show_detail:
        header += "<th>Detail</th>"

    rows = []
    for r in results:
        status_color = _STATUS_COLORS.get(r.status.value, "#333")
        sev_color = _SEVERITY_COLORS.get(r.severity.value, "#333")
        cells = (
            f"<td>{escape(r.audit_id)}</td>"
            f"<td>{escape(r.category)}</td>"
            f"<td>{escape(r.parameter)}</td>"
            f'<td><span class="badge" style="background:{sev_color}">{escape(r.severity.value)}</span></td>'
            f'<td><span class="badge" style="background:{status_color}">{escape(r.status.value)}</span></td>'
            f"<td>{escape(r.expected)}</td>"
            f"<td class=\"actual\">{escape(_fmt_actual(r.actual))}</td>"
        )
        if not compact:
            cells += f"<td>{escape(r.description)}</td><td>{escape(r.remediation)}</td>"
        if show_detail:
            cells += f"<td>{escape(r.detail or '')}</td>"
        rows.append(f"<tr>{cells}</tr>")

    return f'<table class="data"><thead><tr>{header}</tr></thead><tbody>{"".join(rows)}</tbody></table>'


def _fmt_actual(actual) -> str:
    if actual is None:
        return "-"
    if isinstance(actual, list):
        if not actual:
            return "(none)"
        if len(actual) > 5:
            return f"{len(actual)} items"
        return "; ".join(_fmt_item(x) for x in actual)
    return _fmt_item(actual)


def _fmt_item(item) -> str:
    if isinstance(item, dict):
        return ", ".join(f"{k}: {v}" for k, v in item.items())
    return str(item)


def _remediation_list(results: list[CheckResult]) -> str:
    seen = set()
    items = []
    for r in sorted(results, key=_severity_sort_key):
        key = (r.audit_id, r.remediation)
        if key in seen or r.status == CheckStatus.NOT_APPLICABLE:
            continue
        seen.add(key)
        sev_color = _SEVERITY_COLORS.get(r.severity.value, "#333")
        items.append(
            f'<li><span class="badge" style="background:{sev_color}">{escape(r.severity.value)}</span> '
            f"<strong>{escape(r.audit_id)}</strong> ({escape(r.parameter)}): {escape(r.remediation)}</li>"
        )
    if not items:
        return '<p class="muted">No remediation actions required.</p>'
    return f'<ul class="remediation">{"".join(items)}</ul>'


_CSS = """
* { box-sizing: border-box; }
body { margin: 0; }
.page {
  font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
  color: #1b1f24;
  background: #f6f8fa;
  max-width: 1100px;
  margin: 0 auto;
  padding: 24px;
}
.brand-banner {
  display: flex;
  align-items: center;
  gap: 16px;
  background: #001a4d;
  color: #ffffff;
  border-radius: 8px;
  padding: 16px 24px;
  margin-top: 16px;
}
.brand-logo { width: 48px; height: 48px; object-fit: contain; flex-shrink: 0; }
.brand-app { font-size: 1.3rem; font-weight: 700; }
.brand-org { font-size: 0.85rem; color: #c9d6f0; margin-top: 2px; }
header { text-align: center; padding: 24px 0 8px; }
header h1 { margin: 0; font-size: 1.9rem; }
.subtitle { color: #57606a; margin-top: 4px; }
.card {
  background: #ffffff;
  border: 1px solid #d0d7de;
  border-radius: 8px;
  padding: 20px 24px;
  margin-bottom: 20px;
}
.card h2 { margin-top: 0; font-size: 1.25rem; border-bottom: 1px solid #d8dee4; padding-bottom: 8px; }
table.kv { width: 100%; border-collapse: collapse; }
table.kv th { text-align: left; width: 240px; padding: 6px 8px; color: #57606a; font-weight: 600; vertical-align: top; }
table.kv td { padding: 6px 8px; }
table.data { width: 100%; border-collapse: collapse; font-size: 0.88rem; overflow-x: auto; display: block; }
table.data thead, table.data tbody { display: table; width: 100%; table-layout: fixed; }
table.data th, table.data td { border: 1px solid #d8dee4; padding: 6px 8px; text-align: left; vertical-align: top; word-wrap: break-word; }
table.data thead th { background: #f6f8fa; }
table.data tbody tr:nth-child(even) { background: #fafbfc; }
td.actual { max-width: 260px; overflow-wrap: anywhere; }
.badge { color: #fff; padding: 2px 8px; border-radius: 10px; font-size: 0.75rem; font-weight: 600; display: inline-block; overflow-wrap: anywhere; line-height: 1.4; }
.score-row { display: flex; gap: 16px; flex-wrap: wrap; }
.score-card { flex: 1; min-width: 140px; text-align: center; background: #f6f8fa; border: 1px solid #d8dee4; border-radius: 8px; padding: 16px; }
.score-value { font-size: 2rem; font-weight: 700; }
.score-label { color: #57606a; margin-top: 4px; }
.banner { padding: 10px 14px; border-radius: 6px; font-weight: 600; }
.banner-ok { background: #dafbe1; color: #1a7f37; }
.banner-critical { background: #ffebe9; color: #8e1600; }
.notice { background: #fff8c5; border: 1px solid #d4a72c; border-radius: 6px; padding: 10px 14px; }
.muted { color: #57606a; }
ul.remediation { padding-left: 18px; }
ul.remediation li { margin-bottom: 8px; }
details summary { cursor: pointer; font-weight: 600; padding: 6px 0; }
footer { text-align: center; color: #57606a; font-size: 0.85rem; padding: 16px 0; }
@media print {
  .card { break-inside: avoid; }
  .page { background: #ffffff; max-width: none; padding: 0; }
}
"""
