"""
Tests for engine/evaluator.py -- the component responsible for the core
promise of this project: a missing/errored value must become
UNABLE_TO_COLLECT, never a guessed PASS or FAIL.
"""

import unittest

from engine.evaluator import evaluate_rule
from engine.result_model import CheckStatus, CollectionResult, CollectionStatus, Rule


def make_rule(field_path="field", operator="is_true", collector="test", severity="HIGH",
              extra_condition=None, depends_on=None):
    condition = {"operator": operator}
    if extra_condition:
        condition.update(extra_condition)
    return Rule.from_dict({
        "audit_id": "T-001", "category": "Test", "subcategory": "", "parameter": "Param",
        "description": "d", "data_source": "s", "collection_method": "m",
        "collector": collector, "field_path": field_path,
        "expected_condition": condition, "severity": severity, "remediation": "fix",
        "depends_on": depends_on,
    })


def make_collection(data=None, not_applicable=None, errors=None, status=CollectionStatus.OK, collector_error=None):
    return CollectionResult(
        collector_id="test", status=status, data=data or {},
        not_applicable=not_applicable or {}, errors=errors or {}, collector_error=collector_error,
    )


class TestOperators(unittest.TestCase):
    def _eval(self, operator, actual, extra_condition=None):
        rule = make_rule(operator=operator, extra_condition=extra_condition)
        results = {"test": make_collection(data={"field": actual})}
        return evaluate_rule(rule, results).status

    def test_is_true_pass(self):
        self.assertEqual(self._eval("is_true", True), CheckStatus.PASS)

    def test_is_true_fail(self):
        self.assertEqual(self._eval("is_true", False), CheckStatus.FAIL)

    def test_is_false_pass(self):
        self.assertEqual(self._eval("is_false", False), CheckStatus.PASS)

    def test_equals(self):
        self.assertEqual(self._eval("equals", 5, {"value": 5}), CheckStatus.PASS)
        self.assertEqual(self._eval("equals", 6, {"value": 5}), CheckStatus.FAIL)

    def test_in_range(self):
        self.assertEqual(self._eval("in_range", 5, {"min": 1, "max": 10}), CheckStatus.PASS)
        self.assertEqual(self._eval("in_range", 0, {"min": 1, "max": 10}), CheckStatus.FAIL)

    def test_gte(self):
        self.assertEqual(self._eval("gte", 8, {"value": 8}), CheckStatus.PASS)
        self.assertEqual(self._eval("gte", 7, {"value": 8}), CheckStatus.FAIL)

    def test_list_empty(self):
        self.assertEqual(self._eval("list_empty", []), CheckStatus.PASS)
        self.assertEqual(self._eval("list_empty", ["x"]), CheckStatus.FAIL)

    def test_warn_if_true(self):
        self.assertEqual(self._eval("warn_if_true", True), CheckStatus.WARNING)
        self.assertEqual(self._eval("warn_if_true", False), CheckStatus.PASS)

    def test_warn_if_false(self):
        self.assertEqual(self._eval("warn_if_false", False), CheckStatus.WARNING)
        self.assertEqual(self._eval("warn_if_false", True), CheckStatus.PASS)

    def test_warn_if_not_empty(self):
        self.assertEqual(self._eval("warn_if_not_empty", ["x"]), CheckStatus.WARNING)
        self.assertEqual(self._eval("warn_if_not_empty", []), CheckStatus.PASS)

    def test_warn_if_equals(self):
        self.assertEqual(self._eval("warn_if_equals", "Allow", {"value": "Allow"}), CheckStatus.WARNING)
        self.assertEqual(self._eval("warn_if_equals", "Deny", {"value": "Allow"}), CheckStatus.PASS)

    def test_not_none(self):
        self.assertEqual(self._eval("not_none", "anything"), CheckStatus.PASS)
        self.assertEqual(self._eval("not_none", None), CheckStatus.FAIL)

    def test_in_operator(self):
        self.assertEqual(self._eval("in", 5, {"values": [2, 5]}), CheckStatus.PASS)
        self.assertEqual(self._eval("in", 1, {"values": [2, 5]}), CheckStatus.FAIL)


class TestCollectionOutcomes(unittest.TestCase):
    def test_not_applicable_field_never_becomes_pass_or_fail(self):
        rule = make_rule()
        results = {"test": make_collection(not_applicable={"field": "no TPM present"})}
        result = evaluate_rule(rule, results)
        self.assertEqual(result.status, CheckStatus.NOT_APPLICABLE)
        self.assertEqual(result.detail, "no TPM present")

    def test_error_field_never_becomes_pass_or_fail(self):
        rule = make_rule()
        results = {"test": make_collection(errors={"field": "access denied"})}
        result = evaluate_rule(rule, results)
        self.assertEqual(result.status, CheckStatus.UNABLE_TO_COLLECT)
        self.assertEqual(result.detail, "access denied")

    def test_missing_collector_is_unable_to_collect(self):
        rule = make_rule(collector="does_not_exist")
        result = evaluate_rule(rule, {})
        self.assertEqual(result.status, CheckStatus.UNABLE_TO_COLLECT)

    def test_crashed_collector_is_unable_to_collect_not_a_crash(self):
        rule = make_rule()
        results = {"test": make_collection(status=CollectionStatus.ERROR, collector_error="boom")}
        result = evaluate_rule(rule, results)
        self.assertEqual(result.status, CheckStatus.UNABLE_TO_COLLECT)
        self.assertIn("boom", result.detail)

    def test_field_present_but_false_is_evaluated_not_treated_as_missing(self):
        rule = make_rule(operator="is_true")
        results = {"test": make_collection(data={"field": False})}
        result = evaluate_rule(rule, results)
        self.assertEqual(result.status, CheckStatus.FAIL)  # not UNABLE_TO_COLLECT


class TestDependsOn(unittest.TestCase):
    def test_dependency_unmet_short_circuits_to_not_applicable(self):
        rule = make_rule(
            field_path="nla_required",
            operator="is_true",
            depends_on={"field_path": "rdp_enabled", "operator": "equals", "value": True},
        )
        results = {"test": make_collection(data={"rdp_enabled": False, "nla_required": False})}
        result = evaluate_rule(rule, results)
        self.assertEqual(result.status, CheckStatus.NOT_APPLICABLE)

    def test_dependency_met_evaluates_normally(self):
        rule = make_rule(
            field_path="nla_required",
            operator="is_true",
            depends_on={"field_path": "rdp_enabled", "operator": "equals", "value": True},
        )
        results = {"test": make_collection(data={"rdp_enabled": True, "nla_required": True})}
        result = evaluate_rule(rule, results)
        self.assertEqual(result.status, CheckStatus.PASS)

    def test_dependency_errored_is_unable_to_collect(self):
        rule = make_rule(
            field_path="nla_required",
            operator="is_true",
            depends_on={"field_path": "rdp_enabled", "operator": "equals", "value": True},
        )
        results = {"test": make_collection(
            data={"nla_required": True}, errors={"rdp_enabled": "denied"},
        )}
        result = evaluate_rule(rule, results)
        self.assertEqual(result.status, CheckStatus.UNABLE_TO_COLLECT)


if __name__ == "__main__":
    unittest.main()
