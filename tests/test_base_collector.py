"""
Tests for collectors/base.py: the framework-level guarantee that a
collector can never crash the audit, and that partial failures inside a
collector are recorded per-field rather than losing the whole result.
"""

import unittest

from collectors.base import BaseCollector, CollectorContext
from engine.result_model import CollectionStatus


class CrashingCollector(BaseCollector):
    collector_id = "crashing"

    def _collect(self, ctx: CollectorContext) -> None:
        ctx.set("field_before_crash", "value")
        raise RuntimeError("simulated unexpected failure")


class PartialFailureCollector(BaseCollector):
    collector_id = "partial"

    def _collect(self, ctx: CollectorContext) -> None:
        ctx.set("good_field", 42)
        ctx.mark_error("bad_field", "simulated permission error")
        ctx.mark_not_applicable("na_field", "simulated not-applicable case")


class TestBaseCollectorCrashHandling(unittest.TestCase):
    def test_unhandled_exception_becomes_error_status_not_a_crash(self):
        result = CrashingCollector().collect()
        self.assertEqual(result.status, CollectionStatus.ERROR)
        self.assertIn("simulated unexpected failure", result.collector_error)

    def test_partial_data_preserved_alongside_errors(self):
        result = PartialFailureCollector().collect()
        self.assertEqual(result.status, CollectionStatus.OK)
        self.assertEqual(result.get("good_field"), 42)
        self.assertEqual(result.field_state("bad_field"), "error")
        self.assertEqual(result.field_state("na_field"), "not_applicable")
        self.assertEqual(result.field_state("good_field"), "ok")


if __name__ == "__main__":
    unittest.main()
