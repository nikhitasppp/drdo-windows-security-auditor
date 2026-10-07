"""Tests for engine/result_model.py: rule loading and collection-result
field-state resolution."""

import unittest

from engine.result_model import CollectionResult, CollectionStatus, Rule, Severity


class TestRuleFromDict(unittest.TestCase):
    def test_basic_fields(self):
        rule = Rule.from_dict({
            "audit_id": "TEST-001",
            "category": "Test",
            "subcategory": "Sub",
            "parameter": "Param",
            "description": "desc",
            "data_source": "src",
            "collection_method": "method",
            "collector": "system",
            "field_path": "some_field",
            "expected_condition": {"operator": "is_true"},
            "severity": "HIGH",
            "remediation": "fix it",
        })
        self.assertEqual(rule.audit_id, "TEST-001")
        self.assertEqual(rule.severity, Severity.HIGH)
        self.assertTrue(rule.enabled)  # default
        self.assertFalse(rule.requires_admin)  # default
        self.assertIsNone(rule.depends_on)

    def test_depends_on_parsed(self):
        rule = Rule.from_dict({
            "audit_id": "TEST-002",
            "category": "Test",
            "subcategory": "",
            "parameter": "Param",
            "description": "desc",
            "data_source": "src",
            "collection_method": "method",
            "collector": "remote_access",
            "field_path": "rdp_nla_required",
            "expected_condition": {"operator": "is_true"},
            "severity": "HIGH",
            "remediation": "fix it",
            "depends_on": {"field_path": "rdp_enabled", "operator": "equals", "value": True},
        })
        self.assertIsNotNone(rule.depends_on)
        self.assertEqual(rule.depends_on.field_path, "rdp_enabled")
        self.assertEqual(rule.depends_on.value, True)

    def test_disabled_rule(self):
        rule = Rule.from_dict({
            "audit_id": "TEST-003", "category": "Test", "subcategory": "", "parameter": "P",
            "description": "d", "data_source": "s", "collection_method": "m",
            "collector": "system", "field_path": "f",
            "expected_condition": {"operator": "is_true"}, "severity": "LOW",
            "remediation": "r", "enabled": False,
        })
        self.assertFalse(rule.enabled)


class TestCollectionResultFieldState(unittest.TestCase):
    def setUp(self):
        self.result = CollectionResult(
            collector_id="test",
            status=CollectionStatus.OK,
            data={"present_field": True, "false_field": False},
            not_applicable={"na_field": "does not apply here"},
            errors={"error_field": "permission denied"},
        )

    def test_ok_state_for_present_field(self):
        self.assertEqual(self.result.field_state("present_field"), "ok")

    def test_ok_state_for_false_value(self):
        # A legitimate False value must not be confused with "missing".
        self.assertEqual(self.result.field_state("false_field"), "ok")
        self.assertEqual(self.result.get("false_field"), False)

    def test_not_applicable_state(self):
        self.assertEqual(self.result.field_state("na_field"), "not_applicable")

    def test_error_state(self):
        self.assertEqual(self.result.field_state("error_field"), "error")

    def test_missing_state(self):
        self.assertEqual(self.result.field_state("never_set_field"), "ok_missing")


if __name__ == "__main__":
    unittest.main()
