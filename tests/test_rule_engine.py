"""
Integrity tests for the real config/audit_rules.json against the actual
engine and collector registry -- catches typos (unknown operator, unknown
collector, duplicate audit_id) that unit tests using synthetic rules
would never see.
"""

import unittest
from pathlib import Path

from engine.evaluator import _OPERATORS  # noqa: F401 (intentional: validate against real dispatch table)
from engine.rule_engine import COLLECTOR_REGISTRY, load_rules, required_collectors
from engine.scoring import load_severity_config

BASE_DIR = Path(__file__).resolve().parent.parent
RULES_PATH = BASE_DIR / "config" / "audit_rules.json"
SEVERITY_CONFIG_PATH = BASE_DIR / "config" / "severity_config.json"


class TestRuleSetIntegrity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = load_rules(RULES_PATH)

    def test_rules_load_without_error(self):
        self.assertGreater(len(self.rules), 0)

    def test_audit_ids_are_unique(self):
        ids = [r.audit_id for r in self.rules]
        self.assertEqual(len(ids), len(set(ids)), "duplicate audit_id found in audit_rules.json")

    def test_every_rule_collector_is_registered(self):
        unknown = {r.collector for r in self.rules if r.collector not in COLLECTOR_REGISTRY}
        self.assertEqual(unknown, set(), f"rules reference unregistered collector(s): {unknown}")

    def test_every_operator_is_implemented(self):
        from engine.evaluator import _OPERATORS as operators
        unknown = {
            r.expected_condition.get("operator")
            for r in self.rules
            if r.expected_condition.get("operator") not in operators
        }
        self.assertEqual(unknown, set(), f"rules reference unimplemented operator(s): {unknown}")

    def test_depends_on_field_paths_are_plausible_strings(self):
        for r in self.rules:
            if r.depends_on is not None:
                self.assertTrue(r.depends_on.field_path)
                self.assertTrue(r.depends_on.operator)

    def test_required_collectors_is_subset_of_registry(self):
        needed = required_collectors(self.rules)
        self.assertTrue(needed.issubset(set(COLLECTOR_REGISTRY.keys())))

    def test_disabled_rules_excluded_from_required_collectors_when_sole_reference(self):
        # Sanity check that required_collectors respects the `enabled` flag.
        enabled_collectors = {r.collector for r in self.rules if r.enabled}
        self.assertEqual(required_collectors(self.rules), enabled_collectors)


class TestRunCollectorsProgress(unittest.TestCase):
    """run_collectors()'s progress_callback param (added for gui_app.py) is
    optional and purely additive -- these tests use a fake, in-memory
    collector registry so they run instantly and don't touch the real
    system, unlike a real collector."""

    def _fake_collector_class(self):
        from collectors.base import BaseCollector, CollectorContext  # noqa: F401

        class FakeCollector(BaseCollector):
            collector_id = "fake"

            def _collect(self, ctx: "CollectorContext") -> None:
                ctx.set("ok", True)

        return FakeCollector

    def test_progress_callback_called_once_per_collector_in_order(self):
        from engine import rule_engine

        fake_cls = self._fake_collector_class()
        original_registry = rule_engine.COLLECTOR_REGISTRY
        rule_engine.COLLECTOR_REGISTRY = {"fake_a": fake_cls, "fake_b": fake_cls}
        try:
            calls = []
            results = rule_engine.run_collectors(
                {"fake_a", "fake_b"},
                progress_callback=lambda index, total, cid: calls.append((index, total, cid)),
            )
        finally:
            rule_engine.COLLECTOR_REGISTRY = original_registry

        self.assertEqual(calls, [(1, 2, "fake_a"), (2, 2, "fake_b")])
        self.assertEqual(set(results.keys()), {"fake_a", "fake_b"})

    def test_progress_callback_is_optional(self):
        from engine import rule_engine

        fake_cls = self._fake_collector_class()
        original_registry = rule_engine.COLLECTOR_REGISTRY
        rule_engine.COLLECTOR_REGISTRY = {"fake_a": fake_cls}
        try:
            results = rule_engine.run_collectors({"fake_a"})  # no progress_callback -- default None
        finally:
            rule_engine.COLLECTOR_REGISTRY = original_registry

        self.assertIn("fake_a", results)


class TestSeverityConfigIntegrity(unittest.TestCase):
    def test_loads_and_has_required_keys(self):
        config = load_severity_config(SEVERITY_CONFIG_PATH)
        self.assertIn("severity_weights", config)
        self.assertIn("status_credit", config)
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            self.assertIn(severity, config["severity_weights"])

    def test_every_rule_severity_has_a_weight(self):
        config = load_severity_config(SEVERITY_CONFIG_PATH)
        rules = load_rules(RULES_PATH)
        weights = config["severity_weights"]
        for r in rules:
            self.assertIn(r.severity.value, weights)


if __name__ == "__main__":
    unittest.main()
