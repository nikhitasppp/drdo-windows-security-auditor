#!/usr/bin/env python3
"""
Windows 11 System Auditing Framework -- entry point.

Orchestrates: privilege detection -> rule loading -> collection ->
evaluation -> scoring -> reporting. Read-only: this script never modifies
system configuration. See README.md for usage and ARCHITECTURE.md for the
pipeline design.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from engine.evaluator import evaluate_rule  # noqa: E402
from engine.result_model import AuditReport, CollectionResult  # noqa: E402
from engine.rule_engine import load_rules, required_collectors, run_collectors  # noqa: E402
from engine.scoring import compute_scoring, load_severity_config  # noqa: E402
from reporting import console_report, csv_report, html_report, json_report, pdf_report  # noqa: E402
from utils.logging_config import configure_logging, get_logger  # noqa: E402
from utils.permissions import is_admin  # noqa: E402

# When frozen by PyInstaller, __file__ resolves inside the one-time
# extraction temp dir (sys._MEIPASS), not next to the actual .exe -- so
# reports/logs/config written "next to the app" must instead be anchored
# to sys.executable's directory. APP_DIR is that anchor; BUNDLE_DIR is
# where the config JSON files PyInstaller embedded can be found as a
# fallback default.
if getattr(sys, "frozen", False):
    APP_DIR = Path(sys.executable).resolve().parent
    BUNDLE_DIR = Path(getattr(sys, "_MEIPASS", BASE_DIR))
else:
    APP_DIR = BASE_DIR
    BUNDLE_DIR = BASE_DIR


def _default_config_path(filename: str) -> Path:
    """Prefer a config/ folder next to the .exe (so rules can be edited
    without rebuilding); fall back to the copy embedded at build time."""
    external = APP_DIR / "config" / filename
    return external if external.exists() else BUNDLE_DIR / "config" / filename


DEFAULT_RULES_PATH = _default_config_path("audit_rules.json")
DEFAULT_SEVERITY_CONFIG_PATH = _default_config_path("severity_config.json")
DEFAULT_OUTPUT_DIR = APP_DIR / "reports"

_ALL_FORMATS = ("console", "json", "html", "csv", "pdf")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Windows 11 System Auditing Framework")
    parser.add_argument("--rules", default=str(DEFAULT_RULES_PATH), help="Path to audit_rules.json")
    parser.add_argument("--severity-config", default=str(DEFAULT_SEVERITY_CONFIG_PATH),
                         help="Path to severity_config.json")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR), help="Directory to write reports into")
    parser.add_argument("--formats", default="console,json,html,csv,pdf",
                         help="Comma-separated report formats to generate: console,json,html,csv,pdf")
    parser.add_argument("--mock", default=None,
                         help="Path to a fixtures JSON file; runs against that fixed data instead of "
                              "collecting from the live system (see tests/fixtures/)")
    return parser.parse_args(argv)


def load_mock_results(path: str) -> dict[str, CollectionResult]:
    from engine.result_model import CollectionStatus

    with open(path, encoding="utf-8") as f:
        payload = json.load(f)

    results = {}
    for collector_id, spec in payload.items():
        results[collector_id] = CollectionResult(
            collector_id=collector_id,
            status=CollectionStatus(spec.get("status", "OK")),
            data=spec.get("data", {}),
            not_applicable=spec.get("not_applicable", {}),
            errors=spec.get("errors", {}),
            requires_admin=spec.get("requires_admin", False),
            admin_available=spec.get("admin_available", False),
            collector_error=spec.get("collector_error"),
        )
    return results


def run_audit(
    rules_path: str,
    severity_config_path: str,
    mock_path: str | None = None,
    user_name: str | None = None,
    lab: str | None = None,
    remarks: str | None = None,
    audit_start: "datetime | None" = None,
    progress_callback=None,
) -> AuditReport:
    """Run one full audit and return one AuditReport.

    user_name/lab/remarks/audit_start and progress_callback are optional
    and purely additive -- used by gui_app.py, ignored by the plain CLI
    path (main()) below, which calls this with none of them and sees no
    change in behavior. progress_callback is passed straight through to
    run_collectors(); see its docstring for the (index, total, collector_id)
    contract.
    """
    logger = get_logger("main")
    admin = is_admin()
    logger.info("Audit started (admin_available=%s, mock=%s)", admin, bool(mock_path))

    rules = load_rules(rules_path)
    enabled_rules = [r for r in rules if r.enabled]
    logger.info("Loaded %d rules (%d enabled)", len(rules), len(enabled_rules))

    if mock_path:
        results = load_mock_results(mock_path)
    else:
        collector_ids = required_collectors(rules)
        results = run_collectors(collector_ids, progress_callback=progress_callback)

    check_results = [evaluate_rule(r, results) for r in enabled_rules]
    logger.info("Evaluated %d checks", len(check_results))

    severity_config = load_severity_config(severity_config_path)
    scoring = compute_scoring(check_results, severity_config)

    os_info = dict(results["system"].data) if "system" in results else {}

    report = AuditReport(
        generated_at=datetime.now(),
        host_name=socket.gethostname(),
        os_info=os_info,
        is_admin=admin,
        results=check_results,
        collector_errors={cid: cr.collector_error for cid, cr in results.items() if cr.collector_error},
        scoring=scoring,
        user_name=user_name,
        lab=lab,
        remarks=remarks,
        audit_start=audit_start,
        audit_end=datetime.now(),
    )
    logger.info("Audit completed")
    return report


def write_reports(report: AuditReport, output_dir: str, formats: list[str]) -> None:
    logger = get_logger("main")
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = report.generated_at.strftime("%Y%m%d_%H%M%S")

    if "console" in formats:
        print(console_report.generate(report))

    if "json" in formats:
        path = out / f"audit_report_{stamp}.json"
        json_report.generate(report, path)
        logger.info("Wrote JSON report: %s", path)
        print(f"JSON report:  {path}")

    if "csv" in formats:
        path = out / f"audit_report_{stamp}.csv"
        csv_report.generate(report, path)
        logger.info("Wrote CSV report: %s", path)
        print(f"CSV report:   {path}")

    if "html" in formats:
        path = out / f"audit_report_{stamp}.html"
        html_report.generate(report, path)
        logger.info("Wrote HTML report: %s", path)
        print(f"HTML report:  {path}")

    if "pdf" in formats:
        path = out / f"audit_report_{stamp}.pdf"
        try:
            pdf_report.generate(report, path)
            logger.info("Wrote PDF report: %s", path)
            print(f"PDF report:   {path}")
        except pdf_report.PdfGenerationError as e:
            logger.warning("PDF report skipped: %s", e)
            print(f"PDF report:   skipped -- {e}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    configure_logging(str(Path(args.output_dir) / "logs"))

    formats = [f.strip().lower() for f in args.formats.split(",") if f.strip()]
    invalid = set(formats) - set(_ALL_FORMATS)
    if invalid:
        print(f"Unknown report format(s): {', '.join(invalid)}. Valid: {', '.join(_ALL_FORMATS)}", file=sys.stderr)
        return 2

    if not is_admin() and not args.mock:
        print("NOTE: not running as Administrator. Checks requiring elevation will be "
              "reported as UNABLE_TO_COLLECT rather than skipped silently.\n", file=sys.stderr)

    report = run_audit(args.rules, args.severity_config, mock_path=args.mock)
    write_reports(report, args.output_dir, formats)
    return 0


if __name__ == "__main__":
    sys.exit(main())
