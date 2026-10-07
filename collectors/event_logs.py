"""
Event & Log Auditing collector.

Confirmed live on a non-elevated Windows 11 session that even
Get-WinEvent -ListLog Security (metadata only, not reading entries) is
denied without elevation -- this is broader than commonly assumed, so
that check is marked requires_admin in the rule set. The System log's
metadata, and the audit policy for the Logon subcategory (auditpol
/get /subcategory:"Logon" /r, chosen for structured CSV output over
plain text), were also confirmed live.

Get-WinEvent raises a terminating error when a filter matches zero
events ("No events were found...") -- this is a normal, valid outcome
(zero failed logons), not a collection failure, and is handled explicitly
rather than being reported as an error.
"""

from __future__ import annotations

import csv
import io
import subprocess

from collectors.base import BaseCollector, CollectorContext
from utils.powershell import CREATE_NO_WINDOW, run_ps_capture

_SECURITY_LOG_MIN_SIZE_BYTES = 32 * 1024 * 1024  # 32 MB


class EventLogsCollector(BaseCollector):
    collector_id = "event_logs"

    def _collect(self, ctx: CollectorContext) -> None:
        self._collect_security_log_size(ctx)
        self._collect_failed_logons(ctx)
        self._collect_logon_audit_policy(ctx)
        self._collect_system_log(ctx)

    def _collect_security_log_size(self, ctx: CollectorContext) -> None:
        cap = run_ps_capture(
            "Get-WinEvent -ListLog Security -ErrorAction Stop | Select-Object MaximumSizeInBytes"
        )
        if cap.ok and isinstance(cap.data, dict):
            size = cap.data.get("MaximumSizeInBytes")
            ctx.set("security_log_size_adequate", size is not None and int(size) >= _SECURITY_LOG_MIN_SIZE_BYTES)
        else:
            ctx.mark_error("security_log_size_adequate", cap.error or "unknown error querying Security log metadata")

    def _collect_failed_logons(self, ctx: CollectorContext) -> None:
        cap = run_ps_capture(
            "@(Get-WinEvent -LogName Security -ErrorAction Stop -FilterXPath "
            "\"*[System[EventID=4625 and TimeCreated[timediff(@SystemTime) <= 86400000]]]\").Count"
        )
        if cap.ok:
            ctx.set("failed_logon_count_24h", int(cap.data) if cap.data is not None else 0)
            return

        error_text = (cap.error or "")
        if "No events were found" in error_text:
            ctx.set("failed_logon_count_24h", 0)
        else:
            ctx.mark_error("failed_logon_count_24h", error_text or "unknown error querying Security log")

    def _collect_logon_audit_policy(self, ctx: CollectorContext) -> None:
        try:
            proc = subprocess.run(
                ["auditpol", "/get", "/subcategory:Logon", "/r"],
                capture_output=True, text=True, timeout=15,
                creationflags=CREATE_NO_WINDOW,
            )
        except (subprocess.TimeoutExpired, OSError) as e:
            ctx.mark_error("logon_audit_policy_enabled", str(e))
            return

        output = proc.stdout or ""
        if proc.returncode != 0 or "required privilege" in output.lower() or not output.strip():
            ctx.mark_error(
                "logon_audit_policy_enabled",
                "Administrator privileges required to read the local audit policy (auditpol)",
            )
            return

        rows = list(csv.reader(io.StringIO(output)))
        if len(rows) < 2:
            ctx.mark_error("logon_audit_policy_enabled", "Unexpected auditpol output format")
            return

        header, data_row = rows[0], rows[1]
        try:
            inclusion_idx = header.index("Inclusion Setting")
        except ValueError:
            ctx.mark_error("logon_audit_policy_enabled", "Unexpected auditpol CSV header")
            return

        inclusion = data_row[inclusion_idx].strip() if inclusion_idx < len(data_row) else ""
        ctx.set("logon_audit_policy_enabled", inclusion not in ("", "No Auditing"))

    def _collect_system_log(self, ctx: CollectorContext) -> None:
        cap = run_ps_capture("Get-WinEvent -ListLog System -ErrorAction Stop | Select-Object IsEnabled")
        if cap.ok and isinstance(cap.data, dict):
            ctx.set("system_log_available", bool(cap.data.get("IsEnabled")))
        else:
            ctx.mark_error("system_log_available", cap.error or "unknown error querying System log metadata")
