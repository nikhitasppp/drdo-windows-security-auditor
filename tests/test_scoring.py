"""Tests for engine/scoring.py: severity-weighted compliance/risk/coverage
calculation, per the methodology in config/severity_config.json."""

import unittest

from engine.result_model import CheckResult, CheckStatus, Severity
from engine.scoring import compute_scoring

SEVERITY_CONFIG = {
    "severity_weights": {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0},
    "status_credit": {"PASS": 1.0, "WARNING": 0.5, "FAIL": 0.0},
    "statuses_excluded_from_scoring": ["NOT_APPLICABLE", "UNABLE_TO_COLLECT"],
}


def make_result(audit_id, category, severity, status):
    return CheckResult(
        audit_id=audit_id, category=category, subcategory="", parameter="p",
        description="d", data_source="s", collection_method="m",
        expected="x", actual="y", status=CheckStatus(status), severity=Severity(severity),
        remediation="r",
    )


class TestScoring(unittest.TestCase):
    def test_all_pass_gives_100_percent_compliance(self):
        results = [
            make_result("A", "Cat", "HIGH", "PASS"),
            make_result("B", "Cat", "MEDIUM", "PASS"),
        ]
        scoring = compute_scoring(results, SEVERITY_CONFIG)
        self.assertEqual(scoring["compliance_percent"], 100.0)
        self.assertEqual(scoring["risk_score"], 0.0)
        self.assertEqual(scoring["coverage_percent"], 100.0)

    def test_all_fail_gives_zero_percent_compliance(self):
        results = [make_result("A", "Cat", "HIGH", "FAIL")]
        scoring = compute_scoring(results, SEVERITY_CONFIG)
        self.assertEqual(scoring["compliance_percent"], 0.0)
        self.assertEqual(scoring["risk_score"], 100.0)

    def test_warning_gives_half_credit(self):
        results = [make_result("A", "Cat", "HIGH", "WARNING")]
        scoring = compute_scoring(results, SEVERITY_CONFIG)
        self.assertEqual(scoring["compliance_percent"], 50.0)

    def test_critical_failure_weighs_more_than_low(self):
        results = [
            make_result("A", "Cat", "CRITICAL", "FAIL"),
            make_result("B", "Cat", "LOW", "PASS"),
        ]
        scoring = compute_scoring(results, SEVERITY_CONFIG)
        # total weight = 10 + 1 = 11; earned = 0 + 1 = 1 -> 9.1%
        self.assertLess(scoring["compliance_percent"], 20.0)

    def test_not_applicable_excluded_from_denominator(self):
        results = [
            make_result("A", "Cat", "HIGH", "PASS"),
            make_result("B", "Cat", "HIGH", "NOT_APPLICABLE"),
        ]
        scoring = compute_scoring(results, SEVERITY_CONFIG)
        self.assertEqual(scoring["compliance_percent"], 100.0)  # NOT_APPLICABLE doesn't drag it down
        self.assertEqual(scoring["coverage_percent"], 50.0)     # but coverage reflects it

    def test_unable_to_collect_never_counted_as_pass(self):
        results = [make_result("A", "Cat", "CRITICAL", "UNABLE_TO_COLLECT")]
        scoring = compute_scoring(results, SEVERITY_CONFIG)
        self.assertIsNone(scoring["compliance_percent"])  # nothing scoreable was evaluated
        self.assertEqual(scoring["coverage_percent"], 0.0)

    def test_info_severity_excluded_from_scoring_but_counted_in_coverage(self):
        results = [
            make_result("A", "Cat", "INFO", "PASS"),
            make_result("B", "Cat", "HIGH", "FAIL"),
        ]
        scoring = compute_scoring(results, SEVERITY_CONFIG)
        self.assertEqual(scoring["compliance_percent"], 0.0)  # INFO doesn't inflate the score
        self.assertEqual(scoring["coverage_percent"], 100.0)

    def test_category_breakdown_present(self):
        results = [
            make_result("A", "Cat1", "HIGH", "PASS"),
            make_result("B", "Cat2", "HIGH", "FAIL"),
        ]
        scoring = compute_scoring(results, SEVERITY_CONFIG)
        self.assertEqual(scoring["by_category"]["Cat1"]["compliance_percent"], 100.0)
        self.assertEqual(scoring["by_category"]["Cat2"]["compliance_percent"], 0.0)

    def test_counts_match_status_totals(self):
        results = [
            make_result("A", "Cat", "HIGH", "PASS"),
            make_result("B", "Cat", "HIGH", "FAIL"),
            make_result("C", "Cat", "HIGH", "WARNING"),
            make_result("D", "Cat", "HIGH", "NOT_APPLICABLE"),
            make_result("E", "Cat", "HIGH", "UNABLE_TO_COLLECT"),
        ]
        scoring = compute_scoring(results, SEVERITY_CONFIG)
        counts = scoring["counts"]
        self.assertEqual(counts["total_checks"], 5)
        self.assertEqual(counts["passed"], 1)
        self.assertEqual(counts["failed"], 1)
        self.assertEqual(counts["warnings"], 1)
        self.assertEqual(counts["not_applicable"], 1)
        self.assertEqual(counts["unable_to_collect"], 1)


if __name__ == "__main__":
    unittest.main()
