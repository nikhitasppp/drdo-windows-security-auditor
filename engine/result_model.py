"""
Core data model shared by collectors, the rule engine, scoring, and reporting.

Design intent (see ARCHITECTURE.md):
  - Collectors never decide pass/fail. They return a CollectionResult:
    normalized facts plus explicit per-field markers for "not applicable
    on this system" and "could not be collected" (see CollectionResult).
  - The evaluator turns a Rule + the relevant CollectionResult field into
    exactly one CheckResult, using one of five CheckStatus values. It
    never infers PASS/FAIL from missing data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"  # not scored; descriptive/inventory rules only


class CheckStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNABLE_TO_COLLECT = "UNABLE_TO_COLLECT"


class CollectionStatus(str, Enum):
    """Collector-level outcome, distinct from any individual check's status."""
    OK = "OK"                # collector ran; individual fields may still be
                              # marked not-applicable or errored (see below)
    ERROR = "ERROR"          # collector itself failed to run at all
    UNAVAILABLE = "UNAVAILABLE"  # collector could not run due to missing
                                  # privilege/feature, known in advance


@dataclass
class CollectionResult:
    """
    Normalized output of a single collector.

    data:            field_path -> value, for every fact the collector could
                      obtain. Nested facts use dotted paths, e.g.
                      "profiles.public.enabled".
    not_applicable:  field_path -> human-readable reason, for facts that are
                      genuinely inapplicable on this system (e.g. TPM fields
                      on a system with no TPM). Distinct from a collection
                      failure.
    errors:          field_path -> human-readable reason, for facts that
                      should exist but could not be obtained (permission
                      denied, command failed, timeout, etc).
    requires_admin:  True if this collector needs elevation for at least
                      some of its fields.
    admin_available: Whether the process is currently elevated, recorded at
                      collection time (see utils/permissions.py).
    """

    collector_id: str
    status: CollectionStatus
    data: dict[str, Any] = field(default_factory=dict)
    not_applicable: dict[str, str] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)
    requires_admin: bool = False
    admin_available: bool = False
    collected_at: datetime = field(default_factory=datetime.now)
    collector_error: Optional[str] = None  # set when status == ERROR

    def get(self, field_path: str) -> Any:
        return self.data.get(field_path)

    def field_state(self, field_path: str) -> str:
        """Returns 'not_applicable', 'error', 'ok_missing', or 'ok'."""
        if field_path in self.not_applicable:
            return "not_applicable"
        if field_path in self.errors:
            return "error"
        if field_path not in self.data:
            return "ok_missing"
        return "ok"


@dataclass
class Dependency:
    """Optional pre-condition on another field; if unmet, the rule that
    declares this dependency is short-circuited to NOT_APPLICABLE without
    ever evaluating its own condition."""
    field_path: str
    operator: str
    value: Any = None


@dataclass
class Rule:
    audit_id: str
    category: str
    subcategory: str
    parameter: str
    description: str
    data_source: str
    collection_method: str
    collector: str            # which collector module owns field_path
    field_path: str           # dotted path into that collector's CollectionResult.data
    expected_condition: dict[str, Any]   # {"operator": ..., ...operator-specific args}
    severity: Severity
    remediation: str
    enabled: bool = True
    requires_admin: bool = False
    depends_on: Optional[Dependency] = None

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Rule":
        depends_on = None
        if d.get("depends_on"):
            depends_on = Dependency(**d["depends_on"])
        return Rule(
            audit_id=d["audit_id"],
            category=d["category"],
            subcategory=d.get("subcategory", ""),
            parameter=d["parameter"],
            description=d["description"],
            data_source=d["data_source"],
            collection_method=d["collection_method"],
            collector=d["collector"],
            field_path=d["field_path"],
            expected_condition=d["expected_condition"],
            severity=Severity(d["severity"]),
            remediation=d["remediation"],
            enabled=d.get("enabled", True),
            requires_admin=d.get("requires_admin", False),
            depends_on=depends_on,
        )


@dataclass
class CheckResult:
    audit_id: str
    category: str
    subcategory: str
    parameter: str
    description: str
    data_source: str
    collection_method: str
    expected: str        # human-readable description of the expected condition
    actual: Any          # the raw collected value (None if not collected)
    status: CheckStatus
    severity: Severity
    remediation: str
    detail: Optional[str] = None   # extra context, e.g. why UNABLE_TO_COLLECT


@dataclass
class AuditReport:
    generated_at: datetime
    host_name: str
    os_info: dict[str, Any]
    is_admin: bool
    results: list[CheckResult] = field(default_factory=list)
    collector_errors: dict[str, str] = field(default_factory=dict)
    scoring: Optional[dict[str, Any]] = None  # populated by engine/scoring.py

    # GUI/report metadata, all optional -- unset (None) for a plain CLI run
    # (e.g. `python main.py`), populated when run_audit() is called with
    # them (see gui_app.py). Purely additive: no existing caller needs to
    # change, and reporting/json_report.py's asdict() picks these up
    # automatically without any reporting-layer code change.
    user_name: Optional[str] = None
    lab: Optional[str] = None
    remarks: Optional[str] = None
    audit_start: Optional[datetime] = None
    audit_end: Optional[datetime] = None
    application: Optional[str] = None
    organization: Optional[str] = None
    location: Optional[str] = None
    ministry: Optional[str] = None
