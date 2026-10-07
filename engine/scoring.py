"""
Severity-weighted scoring, per the methodology in config/severity_config.json
and documented in FRAMEWORK.md:

  compliance % = (sum of credited weight for evaluated, scored checks)
                  / (sum of weight for evaluated, scored checks) * 100
  risk score    = (sum of weight for FAILed, scored checks)
                  / (sum of weight for evaluated, scored checks) * 100
  coverage %    = (checks that got a real PASS/FAIL/WARNING determination)
                  / (all enabled checks in scope) * 100

INFO-severity checks (weight 0) and checks that ended in NOT_APPLICABLE or
UNABLE_TO_COLLECT are excluded from the compliance/risk denominators --
this is what keeps a low-privilege run from silently scoring as "clean"
just because most checks couldn't be evaluated. Coverage is reported
alongside the score for exactly that reason.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from engine.result_model import CheckResult

_SCORED_STATUSES_DEFAULT_EXCLUDED = {"NOT_APPLICABLE", "UNABLE_TO_COLLECT"}


def load_severity_config(path: str | Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def compute_scoring(results: list[CheckResult], severity_config: dict[str, Any]) -> dict[str, Any]:
    weights = severity_config["severity_weights"]
    credit = severity_config["status_credit"]
    excluded = set(severity_config.get("statuses_excluded_from_scoring", _SCORED_STATUSES_DEFAULT_EXCLUDED))

    counts = {
        "total_checks": len(results),
        "passed": _count(results, "PASS"),
        "failed": _count(results, "FAIL"),
        "warnings": _count(results, "WARNING"),
        "not_applicable": _count(results, "NOT_APPLICABLE"),
        "unable_to_collect": _count(results, "UNABLE_TO_COLLECT"),
    }

    overall = _score_subset(results, weights, credit, excluded)
    by_category: dict[str, Any] = {}
    for category in sorted({r.category for r in results}):
        by_category[category] = _score_subset(
            [r for r in results if r.category == category], weights, credit, excluded
        )

    return {
        "counts": counts,
        "compliance_percent": overall["compliance_percent"],
        "coverage_percent": overall["coverage_percent"],
        "risk_score": overall["risk_score"],
        "by_category": by_category,
    }


def _count(results: list[CheckResult], status_value: str) -> int:
    return sum(1 for r in results if r.status.value == status_value)


def _score_subset(
    results: list[CheckResult],
    weights: dict[str, float],
    credit: dict[str, float],
    excluded_statuses: set[str],
) -> dict[str, Any]:
    scored = [r for r in results if r.severity.value != "INFO"]
    evaluated = [r for r in results if r.status.value not in excluded_statuses]
    scored_evaluated = [r for r in scored if r.status.value not in excluded_statuses]

    total_weight = sum(weights[r.severity.value] for r in scored_evaluated)
    earned_weight = sum(weights[r.severity.value] * credit[r.status.value] for r in scored_evaluated)
    failed_weight = sum(weights[r.severity.value] for r in scored_evaluated if r.status.value == "FAIL")

    compliance_percent = round((earned_weight / total_weight) * 100, 1) if total_weight > 0 else None
    risk_score = round((failed_weight / total_weight) * 100, 1) if total_weight > 0 else None
    coverage_percent = round((len(evaluated) / len(results)) * 100, 1) if results else None

    return {
        "compliance_percent": compliance_percent,
        "risk_score": risk_score,
        "coverage_percent": coverage_percent,
        "scored_check_count": len(scored),
        "total_weight": total_weight,
    }
