"""
Shared collector interface.

Every collector subclasses BaseCollector and implements _collect(ctx),
filling in ctx.data / ctx.not_applicable / ctx.errors as it goes.
BaseCollector.collect() wraps that call so that:
  - an unhandled exception anywhere in a collector never propagates out
    (it becomes CollectionStatus.ERROR, and the audit continues with the
    next collector), and
  - collection start/end and error counts are always logged.

This is the one place that enforces "a collector must never crash the
audit" — individual collectors do not need their own top-level try/except.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from engine.result_model import CollectionResult, CollectionStatus
from utils.logging_config import get_logger
from utils.permissions import is_admin


class CollectorContext:
    """Mutable accumulator a collector fills in during _collect()."""

    def __init__(self, collector_id: str):
        self.collector_id = collector_id
        self.data: dict[str, Any] = {}
        self.not_applicable: dict[str, str] = {}
        self.errors: dict[str, str] = {}
        self.requires_admin = False

    def set(self, field_path: str, value: Any) -> None:
        self.data[field_path] = value

    def mark_not_applicable(self, field_path: str, reason: str) -> None:
        self.not_applicable[field_path] = reason

    def mark_error(self, field_path: str, reason: str) -> None:
        self.errors[field_path] = reason

    def finalize(
        self,
        admin_available: bool,
        status: CollectionStatus = CollectionStatus.OK,
        collector_error: str | None = None,
    ) -> CollectionResult:
        return CollectionResult(
            collector_id=self.collector_id,
            status=status,
            data=self.data,
            not_applicable=self.not_applicable,
            errors=self.errors,
            requires_admin=self.requires_admin,
            admin_available=admin_available,
            collector_error=collector_error,
        )


class BaseCollector(ABC):
    collector_id: str = "base"

    def __init__(self):
        self.logger = get_logger(f"collector.{self.collector_id}")
        self.admin_available = is_admin()

    def collect(self) -> CollectionResult:
        ctx = CollectorContext(self.collector_id)
        self.logger.info("Collection started (admin_available=%s)", self.admin_available)
        try:
            self._collect(ctx)
            self.logger.info(
                "Collection finished: %d fields, %d errors, %d not_applicable",
                len(ctx.data), len(ctx.errors), len(ctx.not_applicable),
            )
            return ctx.finalize(self.admin_available, status=CollectionStatus.OK)
        except Exception as e:  # noqa: BLE001 - deliberate: a collector must never crash the audit
            self.logger.exception("Unhandled exception during collection")
            return ctx.finalize(
                self.admin_available, status=CollectionStatus.ERROR, collector_error=str(e)
            )

    @abstractmethod
    def _collect(self, ctx: CollectorContext) -> None:
        """Populate ctx.data / ctx.not_applicable / ctx.errors."""
        raise NotImplementedError
