"""
PDF report -- built directly in Python with fpdf2, entirely independent
of html_report and of any browser. Earlier attempts routed through a
headless Microsoft Edge instance (--print-to-pdf); that approach proved
unreliable in practice (silent no-ops that were hard to reproduce
consistently, sensitive to whether another Edge window was already
running, sensitive to spaces in the file path). Rendering the PDF
directly removes that entire failure surface -- fpdf2 is a pure-Python
library with no browser, no subprocess, and no OS dialog involved.

fpdf2 is the one report format in this tool that isn't pure standard
library (see requirements.txt) -- a deliberate, contained exception:
every other format needs zero third-party code, this one needs a
small, pure-Python PDF writer with no further dependencies of its own.

Report structure (26 numbered sections; see FRAMEWORK.md for the
scoring methodology this section renders):
  1  Executive Summary (+ administrator-privilege warning box)
  2  System Information
  3  Overall Security / Compliance Score (+ methodology + severity weights)
  4  Category-wise Results (summary table, all categories)
  5-19  One detailed section per category (alphabetical -- however many
        categories audit_rules.json actually defines), every check in
        that category with its own Risk %/Compliance % contribution to
        that category's score
  20 Category / Check Scoring Summary (framework-wide totals)
  21 Failed Checks
  22 Warning Checks
  23 Recommended Remediation
  24 Audit Metadata
  25 Checks That Could Not Be Completed (UNABLE_TO_COLLECT)
  26 Checks Not Applicable (NOT_APPLICABLE)

Every count, score, category, and check table in this module is derived
from the AuditReport passed to generate() (and, for severity weights /
status credit fractions only, from config/severity_config.json -- the
same file engine/scoring.py already scores against). Nothing here
recomputes compliance/risk/coverage: those numbers always come from
report.scoring, exactly as produced by engine/scoring.py.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from fpdf import FPDF
from fpdf.enums import TableCellFillMode
from fpdf.fonts import FontFace

import branding
from engine.result_model import AuditReport, CheckResult, CheckStatus, Severity

_STATUS_COLORS = {
    "PASS": (26, 127, 55),
    "FAIL": (207, 34, 46),
    "WARNING": (154, 103, 0),
    "NOT_APPLICABLE": (87, 96, 106),
    "UNABLE_TO_COLLECT": (102, 57, 186),
}
_SEVERITY_COLORS = {
    "CRITICAL": (142, 22, 0),
    "HIGH": (207, 34, 46),
    "MEDIUM": (154, 103, 0),
    "LOW": (75, 106, 0),
    "INFO": (87, 96, 106),
}
_HEADER_BG = (246, 248, 250)
_ZEBRA_BG = (250, 251, 252)
_BORDER = (208, 215, 222)
_MUTED = (87, 96, 106)
_CODE_BG = (243, 244, 246)

_STATUS_ORDER = {"PASS": 0, "WARNING": 1, "FAIL": 2, "UNABLE_TO_COLLECT": 3, "NOT_APPLICABLE": 4}
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


class PdfGenerationError(RuntimeError):
    """Raised when a PDF cannot be produced."""


# --------------------------------------------------------------------------
# Severity/scoring configuration -- read-only, display purposes only. The
# authoritative compliance/risk/coverage numbers always come from
# report.scoring (engine/scoring.py); this is only used to show the
# severity-weight table and each check's Credit/Weight contribution.
# --------------------------------------------------------------------------

if getattr(sys, "frozen", False):
    _APP_DIR = Path(sys.executable).resolve().parent
    _BUNDLE_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
else:
    _APP_DIR = Path(__file__).resolve().parent.parent
    _BUNDLE_DIR = _APP_DIR


def _default_severity_config_path() -> Path:
    external = _APP_DIR / "config" / "severity_config.json"
    return external if external.exists() else _BUNDLE_DIR / "config" / "severity_config.json"


def _load_scoring_config() -> dict | None:
    """Returns {"weights": {...}, "credit": {...}, "excluded": {...}} or
    None if the config couldn't be read -- callers must degrade gracefully
    (show 'N/A'/'-') rather than fabricate weights."""
    try:
        from engine.scoring import load_severity_config

        cfg = load_severity_config(_default_severity_config_path())
        # "_comment"-prefixed keys are documentation inside the config file
        # (see config/severity_config.json), not real severities/statuses.
        weights = {k: v for k, v in cfg.get("severity_weights", {}).items() if not k.startswith("_")}
        credit = {k: v for k, v in cfg.get("status_credit", {}).items() if not k.startswith("_")}
        return {
            "weights": weights,
            "credit": credit,
            "excluded": set(cfg.get("statuses_excluded_from_scoring", ["NOT_APPLICABLE", "UNABLE_TO_COLLECT"])),
        }
    except Exception:  # noqa: BLE001 -- a missing/corrupt config must never break the PDF
        return None


def _fmt_num(value) -> str:
    if value is None:
        return "-"
    try:
        f = float(value)
    except (TypeError, ValueError):
        return str(value)
    return str(int(f)) if f.is_integer() else f"{f:.1f}"


def _check_risk_compliance(r: CheckResult, category_total_weight: float, cfg: dict | None) -> tuple[str, str]:
    """(risk_pct, compliance_pct) display strings for one check's own
    contribution to ITS CATEGORY's Risk %/Compliance % -- reuses the exact
    per-check terms engine/scoring.py's _score_subset() sums over:
      FAILed check:  risk% = severity weight / category total weight * 100
      PASS/WARNING:  compliance% = (weight * status credit) / total weight * 100
    A check excluded from that denominator (INFO severity, or status in
    statuses_excluded_from_scoring) never contributes, so it displays "NA"
    rather than a misleading 0.0%."""
    if not cfg or r.severity == Severity.INFO or r.severity.value not in cfg["weights"]:
        return "NA", "NA"
    if r.status.value in cfg["excluded"]:
        return "NA", "NA"
    if not category_total_weight:
        return "NA", "NA"
    weight = cfg["weights"][r.severity.value]
    if r.status.value == "FAIL":
        risk_pct = weight / category_total_weight * 100
        compliance_pct = 0.0
    else:
        risk_pct = 0.0
        compliance_pct = weight * cfg["credit"].get(r.status.value, 0) / category_total_weight * 100
    return f"{risk_pct:.1f}%", f"{compliance_pct:.1f}%"


def _score_totals(results: list[CheckResult], cfg: dict) -> tuple[float, float, int]:
    """(total_available_weight, total_earned_weight, scored_evaluated_count)
    across `results`, mirroring engine/scoring.py's _score_subset exactly."""
    weights, credit, excluded = cfg["weights"], cfg["credit"], cfg["excluded"]
    scored_evaluated = [
        r for r in results
        if r.severity != Severity.INFO and r.status.value not in excluded and r.severity.value in weights
    ]
    total = sum(weights[r.severity.value] for r in scored_evaluated)
    earned = sum(weights[r.severity.value] * credit.get(r.status.value, 0) for r in scored_evaluated)
    return total, earned, len(scored_evaluated)


def _score_breakdown(results: list[CheckResult], cfg: dict) -> dict[str, float]:
    """Total/earned/failed weight for `results`, mirroring engine/scoring.py's
    _score_subset() exactly -- used only to render the worked example in
    Section 3 with the same numbers that already produced report.scoring."""
    weights, credit, excluded = cfg["weights"], cfg["credit"], cfg["excluded"]
    scored_evaluated = [
        r for r in results
        if r.severity != Severity.INFO and r.status.value not in excluded and r.severity.value in weights
    ]
    return {
        "total_weight": sum(weights[r.severity.value] for r in scored_evaluated),
        "earned_weight": sum(weights[r.severity.value] * credit.get(r.status.value, 0) for r in scored_evaluated),
        "failed_weight": sum(weights[r.severity.value] for r in scored_evaluated if r.status.value == "FAIL"),
    }


def _s(value) -> str:
    """Sanitize any value to text fpdf2's core (Latin-1) fonts can render,
    never raising on characters outside that range."""
    text = "" if value is None else str(value)
    return text.encode("latin-1", errors="replace").decode("latin-1")


class _ReportPdf(FPDF):
    def header(self):
        pass

    def footer(self):
        self.set_y(-12)
        self.set_draw_color(*_BORDER)
        self.set_line_width(0.2)
        self.line(self.l_margin, self.h - 16, self.w - self.r_margin, self.h - 16)
        self.set_font("helvetica", "I", 8)
        self.set_text_color(*_MUTED)
        self.cell(0, 8, _s(branding.APP_NAME), align="L")
        self.set_xy(self.l_margin, -12)
        self.cell(0, 8, _s(f"Page {self.page_no()}"), align="C")
        self.set_xy(self.l_margin, -12)
        self.cell(self.w - self.l_margin - self.r_margin, 8, _s("Read-only audit report"), align="R")


def generate(report: AuditReport, output_path: str | Path) -> None:
    try:
        pdf = _build(report)
        pdf.output(str(output_path))
    except Exception as e:  # noqa: BLE001 -- a report format must never crash the audit
        raise PdfGenerationError(f"Failed to render PDF: {e}") from e


def _build(report: AuditReport) -> _ReportPdf:
    scoring = report.scoring or {}
    counts = scoring.get("counts", {})
    by_category = scoring.get("by_category", {})
    cfg = _load_scoring_config()

    results = report.results
    results_by_id = {r.audit_id: r for r in results}
    categories = sorted({r.category for r in results})

    failed = sorted([r for r in results if r.status == CheckStatus.FAIL], key=_severity_sort_key)
    warnings = sorted([r for r in results if r.status == CheckStatus.WARNING], key=_severity_sort_key)
    unable = sorted([r for r in results if r.status == CheckStatus.UNABLE_TO_COLLECT], key=lambda r: r.audit_id)
    not_applicable = sorted([r for r in results if r.status == CheckStatus.NOT_APPLICABLE], key=lambda r: r.audit_id)
    critical = [r for r in failed if r.severity == Severity.CRITICAL]

    pdf = _ReportPdf(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.set_margins(14, 14, 14)

    _cover_page(pdf, report)

    pdf.add_page()
    pdf.set_font("helvetica", "B", 20)
    pdf.cell(0, 10, _s("Windows 11 System Audit Report"), new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.set_font("helvetica", "", 11)
    pdf.set_text_color(*_MUTED)
    pdf.cell(0, 7, _s("Automated Security & Compliance Audit"), new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.set_text_color(0, 0, 0)
    pdf.ln(4)

    # ---- 1. Executive Summary ------------------------------------------
    _section_title(pdf, "1. Executive Summary")
    summary = (
        f"This report presents the results of an automated, read-only security and configuration "
        f"audit of {report.host_name}, executed on {report.generated_at.strftime('%d %B %Y at %H:%M:%S')}. "
        f"{len(results)} checks were defined across {len(categories)} categories; "
        f"{counts.get('passed', 0)} passed, {counts.get('failed', 0)} failed, "
        f"{counts.get('warnings', 0)} produced advisory warnings, "
        f"{counts.get('not_applicable', 0)} did not apply to this system, and "
        f"{counts.get('unable_to_collect', 0)} could not be verified"
        + ("" if report.is_admin else " (this run was not elevated; re-run as Administrator for full coverage)")
        + f". {len(critical)} check{'s' if len(critical) != 1 else ''} returned a CRITICAL-severity failure."
    )
    pdf.set_font("helvetica", "", 10)
    pdf.multi_cell(0, 5.5, _s(summary), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    if not report.is_admin:
        _warning_box(
            pdf,
            "ADMINISTRATOR PRIVILEGES REQUIRED",
            "This audit was NOT executed with administrator privileges. Checks that require elevation "
            "(BitLocker, local security policy, audit policy, the Security event log, TPM, Secure Boot) "
            "could not be fully verified and are reported below as UNABLE_TO_COLLECT rather than assumed "
            "safe or unsafe. Re-run this auditor as Administrator to obtain complete audit coverage.",
        )
        pdf.ln(2)

    if critical:
        pdf.set_fill_color(255, 235, 233)
        pdf.set_text_color(142, 22, 0)
        pdf.set_font("helvetica", "B", 10)
        pdf.multi_cell(
            0, 7,
            _s(f"{len(critical)} CRITICAL finding{'s' if len(critical) != 1 else ''} require immediate attention."),
            fill=True, new_x="LMARGIN", new_y="NEXT",
        )
        pdf.set_text_color(0, 0, 0)
        pdf.set_fill_color(0, 0, 0)  # reset: fpdf2 tables otherwise inherit this as an ambient cell background
    else:
        pdf.set_font("helvetica", "", 10)
        pdf.set_text_color(*_MUTED)
        pdf.cell(0, 7, _s("No critical-severity findings."), new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0, 0, 0)
    pdf.ln(3)

    # ---- 2. System Information ------------------------------------------
    _section_title(pdf, "2. System Information")
    _system_information(pdf, report, results_by_id)
    pdf.ln(3)

    # ---- 3. Overall Security / Compliance Score --------------------------
    pdf.add_page()
    _section_title(pdf, "3. Overall Security / Compliance Score")
    _score_row(pdf, scoring)
    pdf.ln(4)
    _scoring_methodology(pdf, cfg, categories, results, by_category)
    pdf.ln(3)

    # ---- 4. Category-wise Results -----------------------------------------
    pdf.add_page()
    _section_title(pdf, "4. Category-wise Results")
    _category_table(pdf, scoring, categories)
    pdf.ln(2)
    pdf.set_font("helvetica", "I", 8.5)
    pdf.set_text_color(*_MUTED)
    pdf.multi_cell(
        0, 4.5,
        _s("Compliance is the share of that category's applicable checks satisfied (credit earned / credit "
           "available, weighted by severity). Risk is the weighted share of applicable checks that FAILed. "
           "Coverage is the share of that category's checks this run could actually evaluate. See Section 20 "
           "for the framework-wide totals and the exact formulas."),
        new_x="LMARGIN", new_y="NEXT",
    )
    pdf.set_text_color(0, 0, 0)

    # ---- 5..(4+N). One section per category --------------------------------
    section_no = 5
    for category in categories:
        cat_results = sorted([r for r in results if r.category == category], key=lambda r: r.audit_id)
        pdf.add_page()
        _section_title(pdf, f"{section_no}. {category}")
        _category_summary(pdf, category, cat_results, by_category.get(category, {}))
        pdf.ln(2)
        _checks_table(pdf, cat_results, cfg, by_category.get(category, {}))
        section_no += 1

    # ---- 20. Category / Check Scoring Summary -------------------------------
    pdf.add_page()
    _section_title(pdf, f"{section_no}. Category / Check Scoring Summary")
    _scoring_summary(pdf, report, results, categories, scoring)
    section_no += 1

    # ---- 21. Failed Checks ---------------------------------------------
    pdf.add_page()
    _section_title(pdf, f"{section_no}. Failed Checks ({len(failed)})")
    _findings_table(pdf, failed) if failed else _muted(pdf, "No failed checks.")
    section_no += 1

    # ---- 22. Warning Checks ----------------------------------------------
    pdf.ln(3)
    _section_title(pdf, f"{section_no}. Warning Checks ({len(warnings)})")
    _findings_table(pdf, warnings) if warnings else _muted(pdf, "No warning checks.")
    section_no += 1

    # ---- 23. Recommended Remediation --------------------------------------
    pdf.add_page()
    _section_title(pdf, f"{section_no}. Recommended Remediation")
    _remediation_list(pdf, failed + warnings)
    section_no += 1

    # ---- 24. Audit Metadata -----------------------------------------------
    pdf.add_page()
    _section_title(pdf, f"{section_no}. Audit Metadata")
    _audit_metadata(pdf, report, categories, results)
    section_no += 1

    # ---- 25. Checks That Could Not Be Completed ----------------------------
    pdf.add_page()
    _section_title(pdf, f"{section_no}. Checks That Could Not Be Completed ({len(unable)})")
    pdf.set_font("helvetica", "I", 8.5)
    pdf.set_text_color(*_MUTED)
    pdf.multi_cell(
        0, 4.5,
        _s("Checks that could not be completed and checks that are not applicable reduce audit coverage "
           "because these checks do not produce a successful PASS, FAIL, or WARNING evaluation of the "
           "corresponding security requirement. Consequently, these checks reduce the coverage "
           "percentage (Section 3); a lower coverage percentage indicates that a smaller proportion of "
           "the audit checks were successfully evaluated. Checks that could not be completed due to "
           "insufficient privileges, unavailable system information, access restrictions, or other "
           "collection errors reduce audit coverage because their security state could not be "
           "evaluated -- an UNABLE_TO_COLLECT result is not automatically treated as a FAIL."),
        new_x="LMARGIN", new_y="NEXT",
    )
    pdf.set_text_color(0, 0, 0)
    pdf.ln(1)
    if unable:
        _findings_table(pdf, unable, show_detail=True)
    else:
        _muted(pdf, "All enabled checks were successfully evaluated.")
    section_no += 1

    # ---- 26. Checks Not Applicable -----------------------------------------
    pdf.ln(3)
    _section_title(pdf, f"{section_no}. Checks Not Applicable ({len(not_applicable)})")
    pdf.set_font("helvetica", "I", 8.5)
    pdf.set_text_color(*_MUTED)
    pdf.multi_cell(
        0, 4.5,
        _s("Checks correctly skipped because their prerequisite didn't hold on this system (e.g. a "
           "Bluetooth check when no Bluetooth adapter is present) -- distinct from checks that failed "
           "to collect (Section 25). Not Applicable checks are not treated as security failures; "
           "however, because they are not evaluated, they reduce the proportion of checks covered by "
           "the assessment. Not-applicable checks are excluded from the compliance/risk denominator; "
           "see Section 3."),
        new_x="LMARGIN", new_y="NEXT",
    )
    pdf.set_text_color(0, 0, 0)
    pdf.ln(1)
    if not_applicable:
        _findings_table(pdf, not_applicable, show_detail=True)
    else:
        _muted(pdf, "No checks were not applicable on this system.")

    pdf.ln(6)
    pdf.set_font("helvetica", "I", 8)
    pdf.set_text_color(*_MUTED)
    pdf.multi_cell(
        0, 5,
        _s("Generated by the Windows 11 System Auditing Framework. Read-only; no system configuration "
           "was modified while producing this report."),
        align="C", new_x="LMARGIN", new_y="NEXT",
    )

    return pdf


# ==========================================================================
# Cover page / generic section helpers
# ==========================================================================

def _cover_page(pdf: FPDF, report: AuditReport) -> None:
    """Page 1: the branded CABS IT AUDITING TOOL cover page. Every numbered
    section (executive summary onward) starts on page 2, unchanged."""
    pdf.add_page()

    system_name = report.host_name
    user_name = report.user_name or "Not specified"
    lab = report.lab or "Not specified"
    audit_time = (report.audit_start or report.generated_at).strftime("%Y-%m-%d %H:%M:%S")

    pdf.set_y(28)
    logo_path = branding.get_logo_path()
    if logo_path is not None:
        logo_w = 32
        pdf.image(str(logo_path), x=(pdf.w - logo_w) / 2, y=pdf.get_y(), w=logo_w)
        pdf.set_y(pdf.get_y() + logo_w + 10)
    else:
        pdf.ln(10)

    pdf.set_text_color(*branding.NAVY_BLUE_RGB)
    pdf.set_font("helvetica", "B", 24)
    pdf.cell(0, 12, _s(branding.APP_NAME), align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)

    pdf.set_text_color(0, 0, 0)
    pdf.set_font("helvetica", "B", 15)
    pdf.cell(0, 9, _s(f"Audit Report for {system_name}"), align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(10)

    pdf.set_font("helvetica", "", 12)
    pdf.cell(0, 8, _s(f"User: {user_name}"), align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, _s(f"Lab: {lab}"), align="C", new_x="LMARGIN", new_y="NEXT")
    if report.remarks:
        pdf.cell(0, 8, _s(f"Remarks: {report.remarks}"), align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(10)

    pdf.set_font("helvetica", "", 11)
    pdf.set_text_color(*_MUTED)
    pdf.cell(0, 7, _s("Audit Date & Time:"), align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("helvetica", "B", 11)
    pdf.cell(0, 7, _s(audit_time), align="C", new_x="LMARGIN", new_y="NEXT")

    pdf.set_y(-70)
    pdf.set_draw_color(*branding.NAVY_BLUE_RGB)
    pdf.set_line_width(0.6)
    pdf.line(pdf.l_margin + 30, pdf.get_y(), pdf.w - pdf.r_margin - 30, pdf.get_y())
    pdf.ln(8)

    pdf.set_text_color(*branding.NAVY_BLUE_RGB)
    pdf.set_font("helvetica", "B", 12)
    pdf.cell(0, 7, _s("DEFENCE RESEARCH & DEVELOPMENT ORGANISATION"), align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("helvetica", "", 11)
    pdf.cell(0, 7, _s("MINISTRY OF DEFENCE"), align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 7, _s(branding.LOCATION), align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)


def _section_title(pdf: FPDF, text: str) -> None:
    pdf.set_font("helvetica", "B", 13)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 8, _s(text), new_x="LMARGIN", new_y="NEXT")
    y = pdf.get_y()
    pdf.set_draw_color(*_BORDER)
    pdf.line(pdf.l_margin, y, pdf.w - pdf.r_margin, y)
    pdf.ln(3)


def _subheading(pdf: FPDF, text: str) -> None:
    pdf.set_font("helvetica", "B", 10.5)
    pdf.set_text_color(*branding.NAVY_BLUE_RGB)
    pdf.cell(0, 7, _s(text), new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.ln(0.5)


def _muted(pdf: FPDF, text: str) -> None:
    pdf.set_font("helvetica", "", 10)
    pdf.set_text_color(*_MUTED)
    pdf.cell(0, 6, _s(text), new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)


def _warning_box(pdf: FPDF, title: str, body: str) -> None:
    pdf.set_fill_color(255, 244, 206)
    pdf.set_draw_color(184, 134, 11)
    pdf.set_line_width(0.4)
    x0, y0 = pdf.get_x(), pdf.get_y()
    w = pdf.w - pdf.l_margin - pdf.r_margin

    pdf.set_font("helvetica", "B", 10)
    title_h = 6
    pdf.set_font("helvetica", "", 9.5)
    body_lines = pdf.multi_cell(w - 6, 5, _s(body), dry_run=True, output="LINES")
    box_h = title_h + len(body_lines) * 5 + 6

    pdf.rect(x0, y0, w, box_h, style="DF")
    pdf.set_xy(x0 + 3, y0 + 3)
    pdf.set_font("helvetica", "B", 10)
    pdf.set_text_color(133, 100, 4)
    pdf.cell(w - 6, title_h, _s(f"[!] {title}"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(x0 + 3)
    pdf.set_font("helvetica", "", 9.5)
    pdf.set_text_color(70, 55, 5)
    pdf.multi_cell(w - 6, 5, _s(body))
    pdf.set_text_color(0, 0, 0)
    pdf.set_fill_color(0, 0, 0)  # reset: fpdf2 tables otherwise inherit this as an ambient cell background
    pdf.set_xy(x0, y0 + box_h + 2)


def _kv_table(pdf: FPDF, rows: list[tuple[str, object]]) -> None:
    pdf.set_font("helvetica", "", 9.5)
    with pdf.table(
        col_widths=(60, 118), borders_layout="NONE", line_height=6,
        text_align=("LEFT", "LEFT"), first_row_as_headings=False, wrapmode="WORD",
    ) as table:
        for label, value in rows:
            row = table.row()
            pdf.set_font("helvetica", "B", 9.5)
            row.cell(_s(label))
            pdf.set_font("helvetica", "", 9.5)
            row.cell(_s(value) if value not in (None, "", []) else "Not Collected")


# ==========================================================================
# Section 2 -- System Information
# ==========================================================================

def _find(results_by_id: dict[str, CheckResult], audit_id: str) -> CheckResult | None:
    return results_by_id.get(audit_id)


def _check_value(results_by_id: dict[str, CheckResult], audit_id: str, fallback: str = "Not Collected") -> str:
    """Human-readable value for a check's `actual`, honoring its status
    when the value itself isn't a plain pass/fail fact (never fabricates
    a value for a check that wasn't found or couldn't be evaluated)."""
    r = _find(results_by_id, audit_id)
    if r is None:
        return fallback
    if r.status == CheckStatus.UNABLE_TO_COLLECT:
        return "Unable to Collect" + (f" ({r.detail})" if r.detail else "")
    if r.status == CheckStatus.NOT_APPLICABLE:
        return "Not Applicable" + (f" ({r.detail})" if r.detail else "")
    return _fmt_actual(r.actual)


def _os_value(os_info: dict, key: str, fallback: str = "Not Collected"):
    value = os_info.get(key)
    return value if value not in (None, "") else fallback


def _system_information(pdf: FPDF, report: AuditReport, results_by_id: dict[str, CheckResult]) -> None:
    os_info = report.os_info or {}

    _subheading(pdf, "Basic System Information")
    version_build = f"{_os_value(os_info, 'os_version', '')} (Build {_os_value(os_info, 'os_build', '?')})".strip()
    cpu = _os_value(os_info, "cpu_name")
    cores = os_info.get("cpu_cores")
    logical = os_info.get("cpu_logical_processors")
    if cores or logical:
        cpu = f"{cpu} ({cores or '?'} cores / {logical or '?'} logical processors)"
    _kv_table(pdf, [
        ("System / Computer Name", _os_value(os_info, "computer_name")),
        ("Operating System", _os_value(os_info, "os_caption")),
        ("OS Version / Build", version_build if version_build.strip() != "(Build ?)" else "Not Collected"),
        ("OS Architecture", _os_value(os_info, "architecture")),
        ("Machine Architecture", _os_value(os_info, "machine")),
        ("Supported Windows Version (10/11)", _check_value(results_by_id, "SYS-024")),
        ("Service Pack", _check_value(results_by_id, "SYS-025")),
        ("Windows Product ID", _check_value(results_by_id, "SYS-026")),
        ("Windows License Status", _check_value(results_by_id, "SYS-027")),
        ("Windows Directory", _os_value(os_info, "windows_directory")),
        ("System Directory", _os_value(os_info, "system_directory")),
        ("OS Install Date", _os_value(os_info, "os_install_date")),
        ("System Uptime (hours)", _os_value(os_info, "uptime_hours")),
        ("Processor / CPU", cpu),
        ("Installed RAM (GB)", _os_value(os_info, "ram_total_gb")),
    ])
    pdf.ln(2)

    _subheading(pdf, "Network Information")
    _kv_table(pdf, [
        ("Connectivity", _os_value(os_info, "connectivity")),
        ("Network Interface", _os_value(os_info, "network_interface")),
        ("Wi-Fi Interface", _os_value(os_info, "wifi_interface")),
        ("Primary IPv4 Address", _os_value(os_info, "ip_address")),
        ("Primary MAC Address", _os_value(os_info, "mac_address")),
        ("DNS Servers Configured", _check_value(results_by_id, "NET-006")),
        ("Proxy Configured", _check_value(results_by_id, "NET-007")),
        ("Domain / Workgroup", _os_value(os_info, "domain_or_workgroup")),
    ])
    pdf.ln(2)

    _subheading(pdf, "Hardware / Platform Information")
    volumes = os_info.get("volumes")
    volumes_str = "; ".join(f"{v.get('drive')} {v.get('free_gb')}GB free / {v.get('size_gb')}GB" for v in volumes) \
        if volumes else "Not Collected"
    _kv_table(pdf, [
        ("System Serial Number", _os_value(os_info, "system_serial_number")),
        ("BIOS Version", _os_value(os_info, "bios_version")),
        ("Firmware Type (UEFI/Legacy)", _os_value(os_info, "firmware_type")),
        ("Secure Boot Enabled", _check_value(results_by_id, "SYS-009")),
        ("TPM Ready", _check_value(results_by_id, "SYS-010")),
        ("BitLocker Enabled (OS Drive)", _check_value(results_by_id, "STG-001")),
        ("Storage Volumes", volumes_str),
        ("Connected USB Devices", _check_value(results_by_id, "DEV-002")),
        ("Bluetooth Adapter Present", _check_value(results_by_id, "DEV-003")),
    ])


# ==========================================================================
# Section 3 -- Overall Security / Compliance Score
# ==========================================================================

def _pct(value) -> str:
    return "N/A" if value is None else f"{value}%"


def _score_row(pdf: FPDF, scoring: dict) -> None:
    labels = ["Compliance", "Risk Score", "Coverage"]
    values = [_pct(scoring.get("compliance_percent")), _pct(scoring.get("risk_score")), _pct(scoring.get("coverage_percent"))]
    captions = [
        "Share of applicable checks satisfied, weighted by severity.",
        "Weighted exposure from checks that FAILed.",
        "Share of checks this run could actually evaluate.",
    ]
    col_w = (pdf.w - pdf.l_margin - pdf.r_margin) / 3
    y0 = pdf.get_y()
    box_h = 30
    for i, (label, value, caption) in enumerate(zip(labels, values, captions)):
        x = pdf.l_margin + i * col_w
        pdf.set_draw_color(*_BORDER)
        pdf.set_fill_color(*_HEADER_BG)
        pdf.rect(x + 1, y0, col_w - 2, box_h, style="DF")
        pdf.set_xy(x + 1, y0 + 3)
        pdf.set_font("helvetica", "B", 18)
        pdf.cell(col_w - 2, 9, _s(value), align="C")
        pdf.set_xy(x + 1, y0 + 12)
        pdf.set_font("helvetica", "B", 9)
        pdf.set_text_color(*_MUTED)
        pdf.cell(col_w - 2, 5, _s(label), align="C")
        pdf.set_xy(x + 2, y0 + 18)
        pdf.set_font("helvetica", "", 7.5)
        pdf.multi_cell(col_w - 4, 3.6, _s(caption), align="C")
        pdf.set_text_color(0, 0, 0)
    pdf.set_fill_color(0, 0, 0)  # reset: fpdf2 tables otherwise inherit this as an ambient cell background
    pdf.set_xy(pdf.l_margin, y0 + box_h + 3)


def _code_block(pdf: FPDF, text: str) -> None:
    pdf.set_font("courier", "", 9)
    pdf.set_fill_color(*_CODE_BG)
    pdf.set_text_color(*branding.NAVY_BLUE_RGB)
    pdf.multi_cell(0, 5.5, _s(text), fill=True, new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.set_fill_color(0, 0, 0)  # reset: fpdf2 tables otherwise inherit this as an ambient cell background


def _body_text(pdf: FPDF, text: str) -> None:
    pdf.set_font("helvetica", "", 9.5)
    pdf.set_text_color(0, 0, 0)
    pdf.multi_cell(0, 5, _s(text), new_x="LMARGIN", new_y="NEXT")


def _ensure_space(pdf: FPDF, height: float) -> None:
    """Force a page break before a block of `height` mm that must not be
    split -- needed for _fraction_formula, whose ruled bar is drawn with
    a raw line() call that (unlike cell()/multi_cell()) doesn't take part
    in fpdf2's automatic page-break handling."""
    if pdf.get_y() + height > pdf.h - pdf.b_margin:
        pdf.add_page()


def _fraction_formula(pdf: FPDF, label: str, numerator: str, denominator: str) -> None:
    """Renders `label` followed by a hand-built stacked fraction --
    numerator, a ruled bar, denominator, with "x 100" set beside the bar
    at its vertical center -- so the formula reads as an actual equation
    rather than a "numerator divided by denominator" sentence. fpdf2 has
    no native fraction support, so the bar is a literal drawn line and
    the three text blocks are positioned around it by hand. The whole
    block's height is computed up front and a page break is forced
    before drawing anything if it would not otherwise fit, so the
    fraction itself is never clipped or split across pages."""
    box_w = pdf.w - pdf.l_margin - pdf.r_margin
    mult_w = 30
    frac_w = box_w - mult_w

    pdf.set_font("courier", "", 9.5)
    num_lines = pdf.multi_cell(frac_w, 5, _s(numerator), align="C", dry_run=True, output="LINES")
    den_lines = pdf.multi_cell(frac_w, 5, _s(denominator), align="C", dry_run=True, output="LINES")
    num_h = max(len(num_lines), 1) * 5
    den_h = max(len(den_lines), 1) * 5
    bar_gap = 1.3
    label_h = 6.5
    content_h = num_h + 2 * bar_gap + den_h
    _ensure_space(pdf, label_h + content_h + 3)

    pdf.set_font("helvetica", "B", 10.5)
    pdf.cell(0, label_h, _s(label), new_x="LMARGIN", new_y="NEXT")

    x0, y0 = pdf.l_margin, pdf.get_y()
    pdf.set_xy(x0, y0)
    pdf.set_font("courier", "", 9.5)
    pdf.multi_cell(frac_w, 5, _s(numerator), align="C")

    bar_y = y0 + num_h + bar_gap
    pdf.set_draw_color(0, 0, 0)
    pdf.set_line_width(0.35)
    pdf.line(x0, bar_y, x0 + frac_w, bar_y)

    pdf.set_xy(x0, bar_y + bar_gap)
    pdf.multi_cell(frac_w, 5, _s(denominator), align="C")

    pdf.set_font("helvetica", "B", 11)
    pdf.set_xy(x0 + frac_w + 4, bar_y - 3.2)
    pdf.cell(mult_w - 4, 6.4, _s("x 100"), align="L")

    pdf.set_xy(x0, y0 + content_h + 3)


def _formula_ref(pdf: FPDF) -> None:
    pdf.set_font("helvetica", "I", 7.5)
    pdf.set_text_color(*_MUTED)
    pdf.cell(0, 4, _s("engine/scoring.py, _score_subset() -- grouped by severity/status"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)


def _scoring_methodology(pdf: FPDF, cfg: dict | None, categories: list[str],
                          results: list[CheckResult], by_category: dict[str, Any]) -> None:
    category_count, check_count = len(categories), len(results)

    _subheading(pdf, "Scoring Methodology")
    _body_text(
        pdf,
        "Every check contributes weight to its category and to the overall score according to its "
        "severity. A check only counts toward Compliance and Risk if it was actually evaluated (its "
        "status is PASS, FAIL or WARNING) and its severity is scored (INFO-severity checks are "
        "inventory/descriptive only and carry zero weight). Checks that ended NOT_APPLICABLE or "
        "UNABLE_TO_COLLECT are excluded from both denominators -- this is deliberate: it keeps a "
        "low-privilege run from scoring as artificially 'clean' just because most checks couldn't be "
        "evaluated. Coverage is reported alongside the score for exactly that reason.",
    )
    pdf.ln(1)

    pdf.set_font("helvetica", "B", 9.5)
    pdf.cell(0, 5.5, _s("Compliance Formula"), new_x="LMARGIN", new_y="NEXT")
    _formula_ref(pdf)
    _fraction_formula(
        pdf, "Compliance % =",
        "Sum over each severity of\n(No. of checks in that group  x  Weight  x  Credit for that status)",
        "Total Weight\n(sum of Weight over all scored, evaluated checks)",
    )
    _body_text(pdf, "In plain language: of the security requirements that actually applied and could be "
                     "checked on this system, how many were satisfied -- weighted so a failed CRITICAL "
                     "check counts far more than a failed LOW check.")
    pdf.ln(1)

    pdf.set_font("helvetica", "B", 9.5)
    pdf.cell(0, 5.5, _s("Risk Formula"), new_x="LMARGIN", new_y="NEXT")
    _formula_ref(pdf)
    _fraction_formula(
        pdf, "Risk Score % =",
        "Sum over each severity of\n(No. of FAILED checks of that severity  x  Weight of that severity)",
        "Total Weight\n(sum of Weight over all scored, evaluated checks)",
    )
    _body_text(pdf, "In plain language: what fraction of the applicable security weight is currently "
                     "exposed because a check outright failed. A higher risk score means more -- and/or "
                     "more severe -- failures.")
    pdf.ln(1)

    pdf.set_font("helvetica", "B", 9.5)
    pdf.cell(0, 5.5, _s("Coverage Formula"), new_x="LMARGIN", new_y="NEXT")
    _formula_ref(pdf)
    _fraction_formula(
        pdf, "Coverage % =",
        "No. of Passed + No. of Failed + No. of Warning checks",
        "Total No. of Checks",
    )
    _body_text(pdf, "In plain language: how much of the framework this run was actually able to inspect. "
                     "\"Successfully evaluated\" means PASS, FAIL or WARNING; \"unable to collect\" means "
                     "the check needed data this run couldn't obtain (typically elevation); \"not "
                     "applicable\" means the check's prerequisite didn't hold on this system (e.g. a "
                     "Bluetooth check with no Bluetooth adapter present) -- neither of the latter two "
                     "counts as coverage.")
    pdf.ln(2)

    if cfg:
        example_category = _pick_example_category(categories)
        if example_category:
            _category_worked_example(
                pdf, example_category,
                sorted([r for r in results if r.category == example_category], key=lambda r: r.audit_id),
                by_category.get(example_category, {}), cfg,
            )
            pdf.ln(2)

    _subheading(pdf, "Severity Weights & Credit")
    if cfg:
        pdf.set_font("helvetica", "", 9)
        with pdf.table(
            col_widths=(50, 40, 88), line_height=6, text_align=("LEFT", "CENTER", "LEFT"),
            headings_style=FontFace(emphasis="B", fill_color=_HEADER_BG), wrapmode="WORD",
        ) as table:
            header = table.row()
            for col in ("Severity", "Weight", ""):
                header.cell(_s(col))
            severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            notes = {
                "CRITICAL": "Immediate risk if failed (e.g. no password required).",
                "HIGH": "Significant risk if failed.",
                "MEDIUM": "Moderate risk if failed.",
                "LOW": "Minor hardening opportunity if failed.",
                "INFO": "Descriptive/inventory only -- not scored.",
            }
            for sev in severity_order:
                if sev not in cfg["weights"]:
                    continue
                row = table.row()
                row.cell(_s(sev), style=FontFace(color=_SEVERITY_COLORS.get(sev, (0, 0, 0)), emphasis="B"))
                row.cell(_fmt_num(cfg["weights"][sev]))
                row.cell(_s(notes.get(sev, "")))
        pdf.ln(1.5)

        pdf.set_font("helvetica", "", 9)
        with pdf.table(
            col_widths=(50, 40, 88), line_height=6, text_align=("LEFT", "CENTER", "LEFT"),
            headings_style=FontFace(emphasis="B", fill_color=_HEADER_BG), wrapmode="WORD",
        ) as table:
            header = table.row()
            for col in ("Status", "Credit Fraction", ""):
                header.cell(_s(col))
            status_notes = {
                "PASS": "Full weight counted toward Compliance.",
                "WARNING": "Half weight counted -- an advisory, not a hard failure.",
                "FAIL": "No weight counted toward Compliance.",
            }
            for status, fraction in cfg["credit"].items():
                row = table.row()
                row.cell(_s(status), style=FontFace(color=_STATUS_COLORS.get(status, (0, 0, 0)), emphasis="B"))
                row.cell(_fmt_num(fraction))
                row.cell(_s(status_notes.get(status, "")))
        pdf.ln(1.5)
        _body_text(
            pdf,
            "Credit: the amount of a check's weight actually counted toward Compliance, based on its "
            "outcome -- weight x credit fraction for its status (e.g. a HIGH-severity check that PASSes "
            "earns its full weight; one that WARNs earns half; one that FAILs earns none).",
        )
    else:
        _muted(pdf, "Severity weight configuration (config/severity_config.json) could not be read; "
                     "weight/credit figures are shown as N/A throughout this report.")
    pdf.ln(2)

    _subheading(pdf, "Audit Scale")
    pdf.set_font("helvetica", "B", 11)
    pdf.set_text_color(*branding.NAVY_BLUE_RGB)
    pdf.cell(0, 7, _s(f"{category_count} Security Categories  |  {check_count} Security Checks"),
             new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.ln(2)

    _severity_summary(pdf, results)
    pdf.ln(2)
    _scoring_basis_and_standards(pdf)


def _pick_example_category(categories: list[str]) -> str | None:
    """Prefers "Authentication & Access Control" for the worked example
    (Section 3) when the loaded audit_rules.json defines it; otherwise
    falls back to the first category alphabetically so the example always
    reflects a category that actually exists in this run."""
    preferred = "Authentication & Access Control"
    if preferred in categories:
        return preferred
    return categories[0] if categories else None


def _checks_used_in_example(pdf: FPDF, cat_results: list[CheckResult]) -> None:
    """Lists every check in the worked-example category with its severity
    and status, so the Compliance/Risk totals that follow can be traced
    back to the individual checks that produced them."""
    pdf.set_font("helvetica", "B", 9), pdf.cell(0, 5.5, _s("Checks Used in This Example"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("helvetica", "", 8.5)
    with pdf.table(
        col_widths=(20, 92, 26, 44), line_height=5.5, text_align=("LEFT", "LEFT", "LEFT", "LEFT"),
        headings_style=FontFace(emphasis="B", fill_color=_HEADER_BG), wrapmode="WORD",
        cell_fill_mode=TableCellFillMode.EVEN_ROWS, cell_fill_color=_ZEBRA_BG,
    ) as table:
        header = table.row()
        for col in ("ID", "Parameter", "Severity", "Status"):
            header.cell(_s(col))
        for r in cat_results:
            row = table.row()
            row.cell(_s(r.audit_id))
            row.cell(_s(r.parameter))
            row.cell(_s(r.severity.value), style=FontFace(color=_SEVERITY_COLORS.get(r.severity.value, (0, 0, 0)), emphasis="B"))
            row.cell(_s(r.status.value), style=FontFace(color=_STATUS_COLORS.get(r.status.value, (0, 0, 0)), emphasis="B"))


def _category_worked_example(pdf: FPDF, category: str, cat_results: list[CheckResult],
                              cat_score: dict, cfg: dict) -> None:
    """A fully worked Compliance/Risk/Coverage calculation for one real
    category from this run, using the exact same totals as report.scoring
    (via _score_breakdown, which mirrors engine/scoring.py's
    _score_subset()) so the result here always matches the category's own
    summary shown in its section below."""
    _subheading(pdf, "Example: Category-Level Calculation")

    if not cat_results:
        _muted(pdf, f'No results were recorded for "{category}" this run.')
        return

    total = len(cat_results)
    passed = sum(1 for r in cat_results if r.status == CheckStatus.PASS)
    failed = sum(1 for r in cat_results if r.status == CheckStatus.FAIL)
    warn = sum(1 for r in cat_results if r.status == CheckStatus.WARNING)
    unable = sum(1 for r in cat_results if r.status == CheckStatus.UNABLE_TO_COLLECT)
    na = sum(1 for r in cat_results if r.status == CheckStatus.NOT_APPLICABLE)

    breakdown = _score_breakdown(cat_results, cfg)
    total_weight, earned_weight, failed_weight = (
        breakdown["total_weight"], breakdown["earned_weight"], breakdown["failed_weight"],
    )
    compliance = cat_score.get("compliance_percent")
    risk = cat_score.get("risk_score")
    coverage = cat_score.get("coverage_percent")

    detail = f"{passed} passed, {failed} failed, {warn} warning{'s' if warn != 1 else ''}"
    if unable:
        detail += f", {unable} unable to collect"
    if na:
        detail += f", {na} not applicable"
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    severity_counts = dict.fromkeys(severity_order, 0)
    for r in cat_results:
        if r.severity.value in severity_counts:
            severity_counts[r.severity.value] += 1
    severity_detail = ", ".join(
        f"{severity_counts[sev]} {sev}" for sev in severity_order if severity_counts[sev]
    )
    _body_text(
        pdf,
        f'To make the formulas above concrete, this example uses the actual results for the '
        f'"{category}" category from this audit run: {total} check{"s" if total != 1 else ""} total '
        f'({detail}), comprising {severity_detail} severity checks.',
    )

    scored_severities = sorted(
        {r.severity.value for r in cat_results
         if r.severity != Severity.INFO and r.status.value not in cfg["excluded"] and r.severity.value in cfg["weights"]},
        key=lambda s: _SEVERITY_ORDER.get(s, 9),
    )
    if scored_severities:
        legend = "     ".join(f"{sev} -> weight = {_fmt_num(cfg['weights'][sev])}" for sev in scored_severities)
        pdf.set_font("courier", "", 8.5)
        pdf.set_text_color(*_MUTED)
        pdf.multi_cell(0, 4.5, _s(legend), new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0, 0, 0)
    pdf.ln(1)

    _checks_used_in_example(pdf, sorted(cat_results, key=lambda r: r.audit_id))
    pdf.ln(1)

    _ensure_space(pdf, 40)  # keep each "X Calculation" heading with its formula, not orphaned by a page break
    pdf.set_font("helvetica", "B", 9.5)
    pdf.cell(0, 5.5, _s("Compliance Calculation"), new_x="LMARGIN", new_y="NEXT")
    if total_weight > 0:
        _fraction_formula(pdf, "Compliance % =", _fmt_num(earned_weight), _fmt_num(total_weight))
        _body_text(pdf, f"= {_fmt_num(earned_weight)} / {_fmt_num(total_weight)} x 100")
        pdf.set_font("helvetica", "B", 10)
        pdf.cell(0, 6, _s(f"= {_pct(compliance)}"), new_x="LMARGIN", new_y="NEXT")
    else:
        _muted(pdf, "No scored, evaluated checks in this category this run -- compliance is not applicable.")
    pdf.ln(2)

    _ensure_space(pdf, 40)
    pdf.set_font("helvetica", "B", 9.5)
    pdf.cell(0, 5.5, _s("Risk Calculation"), new_x="LMARGIN", new_y="NEXT")
    if total_weight > 0:
        _fraction_formula(pdf, "Risk % =", _fmt_num(failed_weight), _fmt_num(total_weight))
        _body_text(pdf, f"= {_fmt_num(failed_weight)} / {_fmt_num(total_weight)} x 100")
        pdf.set_font("helvetica", "B", 10)
        pdf.cell(0, 6, _s(f"= {_pct(risk)}"), new_x="LMARGIN", new_y="NEXT")
    else:
        _muted(pdf, "No scored, evaluated checks in this category this run -- risk is not applicable.")
    pdf.ln(2)

    _ensure_space(pdf, 40)
    pdf.set_font("helvetica", "B", 9.5)
    pdf.cell(0, 5.5, _s("Coverage Calculation"), new_x="LMARGIN", new_y="NEXT")
    _fraction_formula(pdf, "Coverage % =", f"{passed} + {failed} + {warn}", str(total))
    _body_text(pdf, f"= ({passed} + {failed} + {warn}) / {total} x 100")
    pdf.set_font("helvetica", "B", 10)
    pdf.cell(0, 6, _s(f"= {_pct(coverage)}"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("helvetica", "", 9.5)


def _severity_summary(pdf: FPDF, results: list[CheckResult]) -> None:
    """Counts of enabled checks at each severity level, computed from this
    run's actual results -- never hard-coded. INFO is included for a
    complete inventory of check types, but remains outside the scored
    severity scale (see Section 3's methodology text: INFO checks are
    descriptive/inventory only and carry zero weight)."""
    _ensure_space(pdf, 52)  # keep this small, fixed-size table off a lonely last row on the next page
    _subheading(pdf, "Different Types of Checks Based on Severity")
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    counts = dict.fromkeys(order, 0)
    for r in results:
        if r.severity.value in counts:
            counts[r.severity.value] += 1
    total_checks = sum(counts.values())
    total_scored = sum(counts[sev] for sev in order if sev != "INFO")

    pdf.set_font("helvetica", "", 9.5)
    with pdf.table(
        col_widths=(60, 60, 62), line_height=6.5, text_align=("LEFT", "CENTER", "LEFT"),
        headings_style=FontFace(emphasis="B", fill_color=_HEADER_BG), wrapmode="WORD",
    ) as table:
        header = table.row()
        for col in ("Severity", "No. of Checks", ""):
            header.cell(_s(col))
        notes = {
            "CRITICAL": "Immediate risk if failed.",
            "HIGH": "Significant risk if failed.",
            "MEDIUM": "Moderate risk if failed.",
            "LOW": "Minor hardening opportunity if failed.",
            "INFO": "Descriptive/inventory only -- not scored.",
        }
        for sev in order:
            row = table.row()
            row.cell(_s(sev), style=FontFace(color=_SEVERITY_COLORS.get(sev, (0, 0, 0)), emphasis="B"))
            row.cell(str(counts[sev]))
            row.cell(_s(notes[sev]))
    pdf.set_font("helvetica", "I", 8)
    pdf.set_text_color(*_MUTED)
    pdf.cell(
        0, 5,
        _s(f"{total_checks} checks across these five severity types ({total_scored} scored). "
           "INFO-severity checks are descriptive/inventory only and are not part of the scored "
           "severity scale."),
        new_x="LMARGIN", new_y="NEXT",
    )
    pdf.set_text_color(0, 0, 0)


def _scoring_basis_and_standards(pdf: FPDF) -> None:
    _ensure_space(pdf, 45)  # keep the heading from being orphaned at the bottom of a page
    _subheading(pdf, "Scoring Basis and Security Standards")
    _body_text(
        pdf,
        "Severity weights and status credit values are configurable parameters and may be adjusted "
        "according to organizational requirements. Both are read from config/severity_config.json at "
        "audit time and are the values used directly by the compliance and risk calculations in this "
        "report. The security audit framework is designed with reference to established security "
        "guidance and industry standards, including CVSS-based severity concepts, DISA STIG, NIST "
        "security guidance, CIS Benchmarks, and other applicable security baselines.",
    )
    pdf.ln(1)
    _body_text(
        pdf,
        "These parameters can be customized to align the auditing framework with organizational "
        "security policies, risk tolerance, and assessment requirements.",
    )


# ==========================================================================
# Section 4 -- Category-wise Results
# ==========================================================================

def _category_table(pdf: FPDF, scoring: dict, categories: list[str]) -> None:
    pdf.set_font("helvetica", "", 9)
    with pdf.table(
        col_widths=(74, 34, 34, 34), line_height=6,
        text_align=("LEFT", "CENTER", "CENTER", "CENTER"), wrapmode="WORD",
        headings_style=FontFace(emphasis="B", fill_color=_HEADER_BG),
        cell_fill_mode=TableCellFillMode.EVEN_ROWS, cell_fill_color=_ZEBRA_BG,
    ) as table:
        header = table.row()
        for col in ("Category", "Compliance", "Risk Score", "Coverage"):
            header.cell(_s(col))
        for category in categories:
            cat_score = scoring.get("by_category", {}).get(category, {})
            row = table.row()
            row.cell(_s(category))
            row.cell(_pct(cat_score.get("compliance_percent")))
            row.cell(_pct(cat_score.get("risk_score")))
            row.cell(_pct(cat_score.get("coverage_percent")))


# ==========================================================================
# Sections 5..N -- per-category detail
# ==========================================================================

def _category_summary(pdf: FPDF, category: str, results: list[CheckResult], cat_score: dict) -> None:
    total = len(results)
    passed = sum(1 for r in results if r.status == CheckStatus.PASS)
    failed = sum(1 for r in results if r.status == CheckStatus.FAIL)
    warn = sum(1 for r in results if r.status == CheckStatus.WARNING)
    unable = sum(1 for r in results if r.status == CheckStatus.UNABLE_TO_COLLECT)
    na = sum(1 for r in results if r.status == CheckStatus.NOT_APPLICABLE)
    applicable = passed + failed + warn

    _subheading(pdf, "Category Summary")
    pdf.set_font("helvetica", "", 9.5)
    col_w = (pdf.w - pdf.l_margin - pdf.r_margin) / 4
    stats = [
        ("Total Checks", total), ("Passed", passed), ("Failed", failed), ("Warnings", warn),
        ("Unable to Collect", unable), ("Not Applicable", na),
        ("Compliance", _pct(cat_score.get("compliance_percent"))),
        ("Risk", _pct(cat_score.get("risk_score"))),
    ]
    y0 = pdf.get_y()
    for i, (label, value) in enumerate(stats):
        col, line = i % 4, i // 4
        x = pdf.l_margin + col * col_w
        pdf.set_xy(x, y0 + line * 10)
        pdf.set_font("helvetica", "B", 10.5)
        pdf.cell(col_w, 5, _s(str(value)), align="L")
        pdf.set_xy(x, y0 + line * 10 + 5)
        pdf.set_font("helvetica", "", 7.5)
        pdf.set_text_color(*_MUTED)
        pdf.cell(col_w, 4, _s(label), align="L")
        pdf.set_text_color(0, 0, 0)
    pdf.set_xy(pdf.l_margin, y0 + 24)

    coverage = _pct(cat_score.get("coverage_percent"))
    sentence = (
        f"Result: {passed} of {applicable} applicable check{'s' if applicable != 1 else ''} passed"
        + (f", {failed} failed" if failed else "")
        + (f", {warn} produced a warning" if warn else "")
        + f". Coverage for this category: {coverage}"
        + (f" ({unable} check{'s' if unable != 1 else ''} could not be evaluated" +
           (f", {na} not applicable" if na else "") + ")." if (unable or na) else ".")
    )
    pdf.set_font("helvetica", "", 9)
    pdf.set_text_color(*_MUTED)
    pdf.multi_cell(0, 5, _s(sentence), new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)


def _checks_table(pdf: FPDF, results: list[CheckResult], cfg: dict | None, cat_score: dict) -> None:
    category_total_weight = 0.0
    if cfg:
        category_total_weight, _, _ = _score_totals(results, cfg)

    pdf.set_font("helvetica", "", 8)
    widths = (16, 30, 20, 21, 23, 36, 36)
    with pdf.table(
        col_widths=widths, line_height=5.5, text_align="LEFT", wrapmode="WORD",
        headings_style=FontFace(emphasis="B", fill_color=_HEADER_BG),
        cell_fill_mode=TableCellFillMode.EVEN_ROWS, cell_fill_color=_ZEBRA_BG,
    ) as table:
        header = table.row()
        for col in ("ID", "Parameter", "Severity", "Status", "Actual",
                    "Parameter Contribution to Category Risk %", "Parameter Contribution to Category Compliance %"):
            header.cell(_s(col))
        for r in results:
            risk_pct, compliance_pct = _check_risk_compliance(r, category_total_weight, cfg)
            row = table.row()
            row.cell(_s(r.audit_id))
            row.cell(_s(r.parameter))
            row.cell(_s(r.severity.value), style=FontFace(color=_SEVERITY_COLORS.get(r.severity.value, (0, 0, 0))))
            row.cell(_s(r.status.value), style=FontFace(color=_STATUS_COLORS.get(r.status.value, (0, 0, 0)), emphasis="B"))
            row.cell(_s(_fmt_actual(r.actual) if r.actual is not None else (r.detail or "-")))
            row.cell(_s(risk_pct))
            row.cell(_s(compliance_pct))
        total_row = table.row()
        total_row.cell(_s("Total"), style=FontFace(emphasis="B"))
        for _ in range(4):
            total_row.cell("", style=FontFace(emphasis="B"))
        total_row.cell(_s(_pct(cat_score.get("risk_score"))), style=FontFace(emphasis="B"))
        total_row.cell(_s(_pct(cat_score.get("compliance_percent"))), style=FontFace(emphasis="B"))


# ==========================================================================
# Section 20 -- Category / Check Scoring Summary
# ==========================================================================

def _scoring_summary(pdf: FPDF, report: AuditReport, results: list[CheckResult], categories: list[str],
                      scoring: dict) -> None:
    counts = scoring.get("counts", {})
    applicable = counts.get("passed", 0) + counts.get("failed", 0) + counts.get("warnings", 0)

    _subheading(pdf, "Framework Totals")
    _kv_table(pdf, [
        ("Total Categories", len(categories)),
        ("Total Checks", len(results)),
        ("Total Applicable Checks (evaluated)", applicable),
        ("Total number of checks whose status is passed", counts.get("passed", 0)),
        ("Total number of checks whose status is failed", counts.get("failed", 0)),
        ("Total number of checks whose status is warning", counts.get("warnings", 0)),
        ("Total Unable to Collect", counts.get("unable_to_collect", 0)),
        ("Total Not Applicable", counts.get("not_applicable", 0)),
    ])
    pdf.ln(2)

    _kv_table(pdf, [
        ("Overall Compliance", _pct(scoring.get("compliance_percent"))),
        ("Overall Risk Score", _pct(scoring.get("risk_score"))),
        ("Overall Coverage", _pct(scoring.get("coverage_percent"))),
    ])
    pdf.ln(3)

    _subheading(pdf, "How Category Results Roll Up")
    _body_text(
        pdf,
        "Each category's Compliance, Risk and Coverage (Section 4 and Sections 5-" + str(4 + len(categories)) +
        ") is computed the same way as the overall score, but scoped to that category's checks alone "
        "(see Section 3 for the exact formulas). The overall figures above are the same computation "
        "scoped to every applicable check in the entire framework -- not an average of the category "
        "percentages, since categories carry different numbers of checks and different severity mixes.",
    )
    pdf.ln(2)

    _subheading(pdf, "Category Breakdown")
    pdf.set_font("helvetica", "", 7.5)
    with pdf.table(
        col_widths=(52, 13, 14, 13, 16, 13, 15, 15, 12, 12), line_height=6,
        text_align=("LEFT", "CENTER", "CENTER", "CENTER", "CENTER",
                     "CENTER", "CENTER", "CENTER", "CENTER", "CENTER"),
        headings_style=FontFace(emphasis="B", fill_color=_HEADER_BG),
        cell_fill_mode=TableCellFillMode.EVEN_ROWS, cell_fill_color=_ZEBRA_BG, wrapmode="WORD",
    ) as table:
        header = table.row()
        for col in ("Category", "Checks", "Passed", "Failed", "Warnings",
                    "High", "Critical", "Medium", "Low", "Info"):
            header.cell(_s(col))
        totals = dict.fromkeys(
            ("checks", "passed", "failed", "warnings", "high", "critical", "medium", "low", "info"), 0,
        )
        for category in categories:
            cat_results = [r for r in results if r.category == category]
            n_checks = len(cat_results)
            n_passed = sum(1 for r in cat_results if r.status == CheckStatus.PASS)
            n_failed = sum(1 for r in cat_results if r.status == CheckStatus.FAIL)
            n_warn = sum(1 for r in cat_results if r.status == CheckStatus.WARNING)
            n_high = sum(1 for r in cat_results if r.severity == Severity.HIGH)
            n_critical = sum(1 for r in cat_results if r.severity == Severity.CRITICAL)
            n_medium = sum(1 for r in cat_results if r.severity == Severity.MEDIUM)
            n_low = sum(1 for r in cat_results if r.severity == Severity.LOW)
            n_info = sum(1 for r in cat_results if r.severity == Severity.INFO)
            row = table.row()
            row.cell(_s(category))
            row.cell(str(n_checks))
            row.cell(str(n_passed))
            row.cell(str(n_failed))
            row.cell(str(n_warn))
            row.cell(str(n_high))
            row.cell(str(n_critical))
            row.cell(str(n_medium))
            row.cell(str(n_low))
            row.cell(str(n_info))
            totals["checks"] += n_checks
            totals["passed"] += n_passed
            totals["failed"] += n_failed
            totals["warnings"] += n_warn
            totals["high"] += n_high
            totals["critical"] += n_critical
            totals["medium"] += n_medium
            totals["low"] += n_low
            totals["info"] += n_info
        total_row = table.row()
        total_row.cell(_s("Total"), style=FontFace(emphasis="B"))
        for key in ("checks", "passed", "failed", "warnings", "high", "critical", "medium", "low", "info"):
            total_row.cell(str(totals[key]), style=FontFace(emphasis="B"))


# ==========================================================================
# Sections 21/22/25/26 -- flat findings tables; Section 23 -- remediation
# ==========================================================================

def _findings_table(pdf: FPDF, results: list[CheckResult], show_detail: bool = False) -> None:
    if show_detail:
        widths = (16, 32, 18, 26, 40, 50)
        cols = ("ID", "Parameter", "Severity", "Status", "Actual", "Detail")
    else:
        widths = (16, 50, 20, 26, 70)
        cols = ("ID", "Parameter", "Severity", "Status", "Actual")

    pdf.set_font("helvetica", "", 8)
    with pdf.table(
        col_widths=widths, line_height=5.5, text_align="LEFT", wrapmode="WORD",
        headings_style=FontFace(emphasis="B", fill_color=_HEADER_BG),
        cell_fill_mode=TableCellFillMode.EVEN_ROWS, cell_fill_color=_ZEBRA_BG,
    ) as table:
        header = table.row()
        for col in cols:
            header.cell(_s(col))
        for r in results:
            row = table.row()
            row.cell(_s(r.audit_id))
            row.cell(_s(r.parameter))
            row.cell(_s(r.severity.value), style=FontFace(color=_SEVERITY_COLORS.get(r.severity.value, (0, 0, 0))))
            row.cell(_s(r.status.value), style=FontFace(color=_STATUS_COLORS.get(r.status.value, (0, 0, 0)), emphasis="B"))
            row.cell(_s(_fmt_actual(r.actual)))
            if show_detail:
                row.cell(_s(r.detail or ""))


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


def _remediation_list(pdf: FPDF, results: list[CheckResult]) -> None:
    seen = set()
    items = []
    for r in sorted(results, key=_severity_sort_key):
        key = (r.audit_id, r.remediation)
        if key in seen or r.status == CheckStatus.NOT_APPLICABLE or not r.remediation:
            continue
        seen.add(key)
        items.append(r)

    if not items:
        _muted(pdf, "No remediation actions required.")
        return

    for r in items:
        pdf.set_font("helvetica", "B", 9.5)
        pdf.set_text_color(*_SEVERITY_COLORS.get(r.severity.value, (0, 0, 0)))
        pdf.multi_cell(0, 5.5, _s(f"[{r.severity.value}] {r.audit_id} - {r.parameter}"),
                        new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("helvetica", "", 9.5)
        pdf.multi_cell(0, 5.5, _s(r.remediation), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)


# ==========================================================================
# Section 24 -- Audit Metadata
# ==========================================================================

def _audit_metadata(pdf: FPDF, report: AuditReport, categories: list[str], results: list[CheckResult]) -> None:
    os_info = report.os_info or {}
    rows = [
        ("Audit Timestamp", report.generated_at.isoformat(timespec="seconds")),
        ("Host Name", report.host_name),
        ("Operating System", f"{os_info.get('os_caption', 'Unknown')} (Build {os_info.get('os_build', '?')})"),
        ("OS Build", os_info.get("os_build")),
        ("User Name", report.user_name),
        ("Lab", report.lab),
        ("Remarks", report.remarks),
        ("Running as Administrator", "Yes" if report.is_admin else "No"),
        ("Application", report.application or branding.APP_NAME),
        ("Organization", report.organization),
        ("Ministry", report.ministry),
        ("Location", report.location),
    ]
    if report.audit_start:
        rows.append(("Audit Start", report.audit_start.isoformat(timespec="seconds")))
    if report.audit_end:
        rows.append(("Audit End", report.audit_end.isoformat(timespec="seconds")))
    rows += [
        ("Report Generation Timestamp", report.generated_at.isoformat(timespec="seconds")),
        ("Total Checks", len(results)),
        ("Total Categories", len(categories)),
        ("Report Format", "PDF"),
    ]
    _kv_table(pdf, rows)

    if not report.is_admin:
        pdf.ln(2)
        pdf.set_font("helvetica", "I", 9)
        pdf.set_fill_color(255, 248, 197)
        pdf.multi_cell(
            0, 6,
            _s("This audit ran without administrator privileges. Checks that require elevation (BitLocker, "
               "local security policy, audit policy, the Security event log, TPM, Secure Boot) are reported "
               "as UNABLE_TO_COLLECT (Section 25) rather than assumed. Re-run as Administrator for full "
               "coverage."),
            fill=True, new_x="LMARGIN", new_y="NEXT",
        )
        pdf.set_fill_color(0, 0, 0)  # reset: fpdf2 tables otherwise inherit this as an ambient cell background


def _severity_sort_key(r: CheckResult):
    return (_SEVERITY_ORDER.get(r.severity.value, 9), r.audit_id)
