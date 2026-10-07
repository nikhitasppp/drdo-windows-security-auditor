"""
Turns one Rule + the relevant CollectionResult into exactly one CheckResult.

This module is intentionally the only place that maps a collected value to
PASS/FAIL/WARNING/NOT_APPLICABLE/UNABLE_TO_COLLECT. It never guesses: a
missing or errored field always becomes UNABLE_TO_COLLECT, and a field a
collector has explicitly marked inapplicable always becomes NOT_APPLICABLE
-- neither is ever silently treated as PASS or FAIL.
"""

from __future__ import annotations

from typing import Any, Callable

from engine.result_model import CheckResult, CheckStatus, CollectionResult, Rule
from utils.logging_config import get_logger

logger = get_logger("evaluator")


def _op_not_none(actual: Any, cond: dict) -> CheckStatus:
    return CheckStatus.PASS if actual is not None else CheckStatus.FAIL


def _op_is_true(actual: Any, cond: dict) -> CheckStatus:
    return CheckStatus.PASS if bool(actual) is True else CheckStatus.FAIL


def _op_is_false(actual: Any, cond: dict) -> CheckStatus:
    return CheckStatus.PASS if bool(actual) is False else CheckStatus.FAIL


def _op_equals(actual: Any, cond: dict) -> CheckStatus:
    return CheckStatus.PASS if actual == cond["value"] else CheckStatus.FAIL


def _op_not_equals(actual: Any, cond: dict) -> CheckStatus:
    return CheckStatus.PASS if actual != cond["value"] else CheckStatus.FAIL


def _op_in(actual: Any, cond: dict) -> CheckStatus:
    return CheckStatus.PASS if actual in cond["values"] else CheckStatus.FAIL


def _op_not_in(actual: Any, cond: dict) -> CheckStatus:
    return CheckStatus.PASS if actual not in cond["values"] else CheckStatus.FAIL


def _op_gte(actual: Any, cond: dict) -> CheckStatus:
    return CheckStatus.PASS if actual is not None and actual >= cond["value"] else CheckStatus.FAIL


def _op_lte(actual: Any, cond: dict) -> CheckStatus:
    return CheckStatus.PASS if actual is not None and actual <= cond["value"] else CheckStatus.FAIL


def _op_gt(actual: Any, cond: dict) -> CheckStatus:
    return CheckStatus.PASS if actual is not None and actual > cond["value"] else CheckStatus.FAIL


def _op_lt(actual: Any, cond: dict) -> CheckStatus:
    return CheckStatus.PASS if actual is not None and actual < cond["value"] else CheckStatus.FAIL


def _op_in_range(actual: Any, cond: dict) -> CheckStatus:
    return CheckStatus.PASS if actual is not None and cond["min"] <= actual <= cond["max"] else CheckStatus.FAIL


def _op_list_empty(actual: Any, cond: dict) -> CheckStatus:
    return CheckStatus.PASS if not (actual or []) else CheckStatus.FAIL


def _op_list_not_empty(actual: Any, cond: dict) -> CheckStatus:
    return CheckStatus.PASS if (actual or []) else CheckStatus.FAIL


def _op_warn_if_true(actual: Any, cond: dict) -> CheckStatus:
    return CheckStatus.WARNING if bool(actual) else CheckStatus.PASS


def _op_warn_if_false(actual: Any, cond: dict) -> CheckStatus:
    return CheckStatus.PASS if bool(actual) else CheckStatus.WARNING


def _op_warn_if_not_empty(actual: Any, cond: dict) -> CheckStatus:
    return CheckStatus.WARNING if (actual or []) else CheckStatus.PASS


def _op_warn_if_equals(actual: Any, cond: dict) -> CheckStatus:
    return CheckStatus.WARNING if actual == cond["value"] else CheckStatus.PASS


_OPERATORS: dict[str, Callable[[Any, dict], CheckStatus]] = {
    "not_none": _op_not_none,
    "is_true": _op_is_true,
    "is_false": _op_is_false,
    "equals": _op_equals,
    "not_equals": _op_not_equals,
    "in": _op_in,
    "not_in": _op_not_in,
    "gte": _op_gte,
    "lte": _op_lte,
    "gt": _op_gt,
    "lt": _op_lt,
    "in_range": _op_in_range,
    "list_empty": _op_list_empty,
    "list_not_empty": _op_list_not_empty,
    "warn_if_true": _op_warn_if_true,
    "warn_if_false": _op_warn_if_false,
    "warn_if_not_empty": _op_warn_if_not_empty,
    "warn_if_equals": _op_warn_if_equals,
}


def describe_condition(condition: dict) -> str:
    op = condition.get("operator")
    if op == "not_none":
        return "data available"
    if op == "is_true":
        return "enabled"
    if op == "is_false":
        return "disabled"
    if op == "equals":
        return f"= {condition['value']}"
    if op == "not_equals":
        return f"≠ {condition['value']}"
    if op == "in":
        return f"one of {condition['values']}"
    if op == "not_in":
        return f"not one of {condition['values']}"
    if op == "gte":
        return f">= {condition['value']}"
    if op == "lte":
        return f"<= {condition['value']}"
    if op == "gt":
        return f"> {condition['value']}"
    if op == "lt":
        return f"< {condition['value']}"
    if op == "in_range":
        return f"between {condition['min']} and {condition['max']}"
    if op in ("list_empty",):
        return "none present"
    if op in ("list_not_empty",):
        return "at least one present"
    if op == "warn_if_true":
        return "should not be enabled (advisory)"
    if op == "warn_if_false":
        return "should be enabled (advisory)"
    if op == "warn_if_not_empty":
        return "none present (advisory)"
    if op == "warn_if_equals":
        return f"should not be {condition['value']} (advisory)"
    return str(condition)


def _evaluate_condition(actual: Any, condition: dict) -> CheckStatus:
    op = condition.get("operator")
    func = _OPERATORS.get(op)
    if func is None:
        raise ValueError(f"Unknown operator: {op}")
    return func(actual, condition)


def evaluate_rule(rule: Rule, results: dict[str, CollectionResult]) -> CheckResult:
    """Evaluate a single rule against the full set of collector results."""
    expected_desc = describe_condition(rule.expected_condition)

    collection = results.get(rule.collector)
    if collection is None:
        return _result(rule, expected_desc, None, CheckStatus.UNABLE_TO_COLLECT,
                        detail=f"Collector '{rule.collector}' did not run")

    if collection.status.value == "ERROR":
        return _result(rule, expected_desc, None, CheckStatus.UNABLE_TO_COLLECT,
                        detail=f"Collector '{rule.collector}' failed: {collection.collector_error}")

    if rule.depends_on is not None:
        dep = rule.depends_on
        dep_state = collection.field_state(dep.field_path)
        if dep_state == "not_applicable":
            return _result(rule, expected_desc, None, CheckStatus.NOT_APPLICABLE,
                            detail=collection.not_applicable[dep.field_path])
        if dep_state in ("error", "ok_missing"):
            reason = collection.errors.get(dep.field_path, "dependency field not collected")
            return _result(rule, expected_desc, None, CheckStatus.UNABLE_TO_COLLECT,
                            detail=f"Could not evaluate prerequisite '{dep.field_path}': {reason}")

        dep_actual = collection.get(dep.field_path)
        try:
            dep_condition = {"operator": dep.operator, "value": dep.value}
            dep_met = _evaluate_condition(dep_actual, dep_condition) == CheckStatus.PASS
        except Exception as e:  # noqa: BLE001
            return _result(rule, expected_desc, None, CheckStatus.UNABLE_TO_COLLECT,
                            detail=f"Error evaluating prerequisite: {e}")

        if not dep_met:
            return _result(rule, expected_desc, dep_actual, CheckStatus.NOT_APPLICABLE,
                            detail=f"Not applicable: '{dep.field_path}' = {dep_actual!r}, expected {dep.value!r}")

    field_state = collection.field_state(rule.field_path)
    if field_state == "not_applicable":
        return _result(rule, expected_desc, None, CheckStatus.NOT_APPLICABLE,
                        detail=collection.not_applicable[rule.field_path])
    if field_state in ("error", "ok_missing"):
        reason = collection.errors.get(rule.field_path, "no data collected for this field")
        return _result(rule, expected_desc, None, CheckStatus.UNABLE_TO_COLLECT, detail=reason)

    actual = collection.get(rule.field_path)
    try:
        status = _evaluate_condition(actual, rule.expected_condition)
    except Exception as e:  # noqa: BLE001
        logger.warning("Evaluation error for %s: %s", rule.audit_id, e)
        return _result(rule, expected_desc, actual, CheckStatus.UNABLE_TO_COLLECT,
                        detail=f"Evaluation error: {e}")

    return _result(rule, expected_desc, actual, status)


def _result(rule: Rule, expected_desc: str, actual: Any, status: CheckStatus, detail: str | None = None) -> CheckResult:
    return CheckResult(
        audit_id=rule.audit_id,
        category=rule.category,
        subcategory=rule.subcategory,
        parameter=rule.parameter,
        description=rule.description,
        data_source=rule.data_source,
        collection_method=rule.collection_method,
        expected=expected_desc,
        actual=actual,
        status=status,
        severity=rule.severity,
        remediation=rule.remediation,
        detail=detail,
    )
