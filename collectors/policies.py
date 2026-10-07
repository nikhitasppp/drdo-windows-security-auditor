"""
System Configuration & Policies collector.

PowerShell execution policy is read via Get-ExecutionPolicy -List with
each enum cast to string inside the PowerShell expression (confirmed live
that the bare enum otherwise serializes as an ambiguous integer). The
'Process' scope is deliberately dropped: this auditor always launches
PowerShell with -ExecutionPolicy Bypass for its own commands, so that
scope would otherwise always read "Bypass" regardless of the system's
real persistent policy -- confirmed live on this development host, where
Process-scope Bypass was an artifact of the invoking shell, not a system
setting.

Script-block-logging and device-install-restriction state are read
directly from the registry: their absence is itself the (accurate,
verified) answer of "not configured" and is reported as False, not as a
collection failure.
"""

from __future__ import annotations

from collectors.base import BaseCollector, CollectorContext
from utils import registry
from utils.helpers import as_list
from utils.powershell import run_ps_capture

_SCRIPT_BLOCK_LOGGING_KEY = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
_DEVICE_INSTALL_RESTRICTIONS_KEY = r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"

_RISKY_POLICIES = {"Unrestricted", "Bypass"}


class PoliciesCollector(BaseCollector):
    collector_id = "policies"

    def _collect(self, ctx: CollectorContext) -> None:
        self._collect_execution_policy(ctx)
        self._collect_script_block_logging(ctx)
        self._collect_device_install_restriction(ctx)

    def _collect_execution_policy(self, ctx: CollectorContext) -> None:
        cap = run_ps_capture(
            "Get-ExecutionPolicy -List -ErrorAction Stop | "
            "ForEach-Object { [PSCustomObject]@{ Scope = $_.Scope.ToString(); ExecutionPolicy = $_.ExecutionPolicy.ToString() } }"
        )
        if not cap.ok:
            ctx.mark_error("risky_execution_policy_scopes", cap.error or "unknown error querying Get-ExecutionPolicy")
            return

        entries = [e for e in as_list(cap.data) if isinstance(e, dict)]
        ctx.set("execution_policy_by_scope", entries)
        risky = [
            e["Scope"] for e in entries
            if e.get("Scope") != "Process" and e.get("ExecutionPolicy") in _RISKY_POLICIES
        ]
        ctx.set("risky_execution_policy_scopes", risky)

    def _collect_script_block_logging(self, ctx: CollectorContext) -> None:
        result = registry.read_value("HKLM", _SCRIPT_BLOCK_LOGGING_KEY, "EnableScriptBlockLogging")
        if result.error:
            ctx.mark_error("script_block_logging_enabled", result.error)
        elif not result.exists:
            ctx.set("script_block_logging_enabled", False)
        else:
            ctx.set("script_block_logging_enabled", bool(result.value))

    def _collect_device_install_restriction(self, ctx: CollectorContext) -> None:
        result = registry.key_exists("HKLM", _DEVICE_INSTALL_RESTRICTIONS_KEY)
        if result.error:
            ctx.mark_error("device_install_restriction_enabled", result.error)
        else:
            ctx.set("device_install_restriction_enabled", result.exists)
