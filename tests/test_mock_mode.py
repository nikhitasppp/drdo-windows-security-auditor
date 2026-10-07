"""
Tests for the mock/test mode (main.load_mock_results + main.run_audit),
which lets rule evaluation, scoring, and reporting be exercised end-to-end
without touching the real system -- required for CI and for development
on non-Windows machines.
"""

import unittest
from pathlib import Path

import main
from engine.result_model import CheckStatus

FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "mock_results.json"
RULES_PATH = main.DEFAULT_RULES_PATH
SEVERITY_CONFIG_PATH = main.DEFAULT_SEVERITY_CONFIG_PATH


class TestMockMode(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = main.run_audit(str(RULES_PATH), str(SEVERITY_CONFIG_PATH), mock_path=str(FIXTURE_PATH))

    def test_report_produced_without_touching_real_system(self):
        self.assertGreater(len(self.report.results), 0)

    def test_all_five_statuses_appear_in_the_fixture(self):
        statuses = {r.status for r in self.report.results}
        for expected in (CheckStatus.PASS, CheckStatus.FAIL, CheckStatus.WARNING,
                          CheckStatus.NOT_APPLICABLE, CheckStatus.UNABLE_TO_COLLECT):
            self.assertIn(expected, statuses, f"fixture never produces {expected}")

    def test_scoring_present_and_consistent_with_counts(self):
        scoring = self.report.scoring
        self.assertIsNotNone(scoring)
        total = sum(scoring["counts"].values()) - scoring["counts"]["total_checks"]
        self.assertEqual(total, scoring["counts"]["total_checks"])

    def test_known_fixture_fail_is_reported(self):
        # security.defender_antivirus_enabled = False in the fixture.
        sec002 = next(r for r in self.report.results if r.audit_id == "SEC-002")
        self.assertEqual(sec002.status, CheckStatus.FAIL)

    def test_known_fixture_not_applicable_dependency_is_reported(self):
        # remote_access.rdp_enabled = False -> RDP-002 depends_on short-circuits.
        rdp002 = next(r for r in self.report.results if r.audit_id == "RDP-002")
        self.assertEqual(rdp002.status, CheckStatus.NOT_APPLICABLE)

    def test_can_generate_all_report_formats_from_mock_report(self):
        import tempfile
        from reporting import console_report, csv_report, html_report, json_report

        with tempfile.TemporaryDirectory() as tmp:
            console_text = console_report.generate(self.report)
            self.assertIn("WINDOWS 11 SYSTEM AUDIT REPORT", console_text)

            json_report.generate(self.report, Path(tmp) / "r.json")
            csv_report.generate(self.report, Path(tmp) / "r.csv")
            html_report.generate(self.report, Path(tmp) / "r.html")

            self.assertTrue((Path(tmp) / "r.json").exists())
            self.assertTrue((Path(tmp) / "r.csv").exists())
            self.assertTrue((Path(tmp) / "r.html").exists())


if __name__ == "__main__":
    unittest.main()
