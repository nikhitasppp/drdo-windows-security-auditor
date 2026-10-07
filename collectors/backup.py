"""
Backup & Recovery collector.

System Restore: checked in two stages. First, the Group Policy override
HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore\\DisableSR
is read without elevation -- if present and set, that alone is a
definite answer. Otherwise, Get-ComputerRestorePoint is used: confirmed
live that it requires elevation ("Access denied" when not admin), and is
documented to throw "System Restore is disabled on this computer" when
protection is off system-wide, succeeding (even with zero existing
restore points) otherwise. This replaced an earlier version of this
collector that only checked the registry key and reported
UNABLE_TO_COLLECT whenever no policy override was present -- confirmed
live that neither the registry nor the SystemRestoreConfig WMI class
expose a direct per-drive enabled/disabled flag on this Windows 11
build, which is why Get-ComputerRestorePoint's success/failure is used
as the actual signal instead.

Recovery partition presence: Get-Partition, confirmed to run without
elevation.
"""

from __future__ import annotations

from collectors.base import BaseCollector, CollectorContext
from utils import registry
from utils.helpers import as_list
from utils.powershell import run_ps_capture

_SYSTEM_RESTORE_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore"


class BackupCollector(BaseCollector):
    collector_id = "backup"

    def _collect(self, ctx: CollectorContext) -> None:
        self._collect_system_restore(ctx)
        self._collect_backup_service(ctx)
        self._collect_recovery_partition(ctx)

    def _collect_system_restore(self, ctx: CollectorContext) -> None:
        disable_sr = registry.read_value("HKLM", _SYSTEM_RESTORE_KEY, "DisableSR")
        if disable_sr.error:
            ctx.mark_error("system_restore_enabled", disable_sr.error)
            return
        if disable_sr.exists and int(disable_sr.value) == 1:
            ctx.set("system_restore_enabled", False)
            return

        cap = run_ps_capture("@(Get-ComputerRestorePoint -ErrorAction Stop).Count")
        if cap.ok:
            ctx.set("system_restore_enabled", True)
            return

        error_text = cap.error or ""
        if "disabled" in error_text.lower():
            ctx.set("system_restore_enabled", False)
        else:
            ctx.mark_error(
                "system_restore_enabled",
                f"Could not determine System Restore state via Get-ComputerRestorePoint: {error_text or 'unknown error'}",
            )

    def _collect_backup_service(self, ctx: CollectorContext) -> None:
        cap = run_ps_capture(
            "Get-Service -Name SDRSVC -ErrorAction Stop | "
            "ForEach-Object { [PSCustomObject]@{ Status = $_.Status.ToString() } }"
        )
        if cap.ok and isinstance(cap.data, dict):
            ctx.set("sdrsvc_service_state", cap.data.get("Status"))
        else:
            ctx.mark_error("sdrsvc_service_state", cap.error or "unknown error querying SDRSVC service")

    def _collect_recovery_partition(self, ctx: CollectorContext) -> None:
        cap = run_ps_capture("Get-Partition -ErrorAction Stop | Select-Object Type")
        if cap.ok:
            partitions = [p for p in as_list(cap.data) if isinstance(p, dict)]
            ctx.set("recovery_partition_present", any(p.get("Type") == "Recovery" for p in partitions))
        else:
            ctx.mark_error("recovery_partition_present", cap.error or "unknown error querying Get-Partition")
