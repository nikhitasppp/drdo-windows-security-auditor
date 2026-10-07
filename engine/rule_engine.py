"""
Loads audit_rules.json and orchestrates running collectors against it.

Deliberately independent of any specific collector's internals: it only
knows the collector_id -> Collector class mapping (COLLECTOR_REGISTRY) and
the generic BaseCollector.collect() -> CollectionResult contract. Adding a
new collector means adding one entry here and rules that reference it --
nothing else in the engine changes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable, Optional

from collectors.applications import ApplicationsCollector
from collectors.authentication import AuthenticationCollector
from collectors.backup import BackupCollector
from collectors.base import BaseCollector
from collectors.browser import BrowserCollector
from collectors.devices import DevicesCollector
from collectors.event_logs import EventLogsCollector
from collectors.firewall import FirewallCollector
from collectors.network import NetworkCollector
from collectors.policies import PoliciesCollector
from collectors.processes import ProcessesCollector
from collectors.remote_access import RemoteAccessCollector
from collectors.security import SecurityCollector
from collectors.services import ServicesCollector
from collectors.storage import StorageCollector
from collectors.system import SystemCollector
from collectors.updates import UpdatesCollector
from collectors.users import UsersCollector
from engine.result_model import CollectionResult, Rule
from utils.logging_config import get_logger

logger = get_logger("rule_engine")

COLLECTOR_REGISTRY: dict[str, type[BaseCollector]] = {
    "system": SystemCollector,
    "users": UsersCollector,
    "authentication": AuthenticationCollector,
    "security": SecurityCollector,
    "firewall": FirewallCollector,
    "network": NetworkCollector,
    "updates": UpdatesCollector,
    "services": ServicesCollector,
    "processes": ProcessesCollector,
    "applications": ApplicationsCollector,
    "remote_access": RemoteAccessCollector,
    "policies": PoliciesCollector,
    "storage": StorageCollector,
    "event_logs": EventLogsCollector,
    "devices": DevicesCollector,
    "browser": BrowserCollector,
    "backup": BackupCollector,
}


def load_rules(path: str | Path) -> list[Rule]:
    with open(path, encoding="utf-8") as f:
        payload = json.load(f)
    return [Rule.from_dict(r) for r in payload["rules"]]


def required_collectors(rules: list[Rule]) -> set[str]:
    return {r.collector for r in rules if r.enabled}


def run_collectors(
    collector_ids: set[str] | None = None,
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
) -> dict[str, CollectionResult]:
    """Run each requested collector and return {collector_id: CollectionResult}.
    A collector that isn't registered is simply skipped (evaluator will report
    any rule that needs it as UNABLE_TO_COLLECT).

    progress_callback, if given, is called as (index, total, collector_id)
    -- 1-based index, total = number of collectors that will actually run --
    immediately before each collector's collect() runs. Optional and purely
    additive: existing callers passing nothing see no change in behavior."""
    ids = collector_ids if collector_ids is not None else set(COLLECTOR_REGISTRY.keys())
    sorted_ids = sorted(ids)
    total = len(sorted_ids)
    results: dict[str, CollectionResult] = {}
    for index, collector_id in enumerate(sorted_ids, start=1):
        collector_cls = COLLECTOR_REGISTRY.get(collector_id)
        if collector_cls is None:
            logger.warning("No collector registered for id '%s'", collector_id)
            continue
        if progress_callback is not None:
            progress_callback(index, total, collector_id)
        logger.info("Running collector: %s", collector_id)
        results[collector_id] = collector_cls().collect()
    return results
