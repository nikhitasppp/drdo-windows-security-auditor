"""
Windows Update & Patch Management collector.

Sources: Get-Service wuauserv for the update service state, and
Win32_QuickFixEngineering for installed-update recency. This tool
deliberately does NOT query for pending/available updates: doing so
requires either the WU Agent COM UpdateSearcher or contacting a
WSUS/Windows Update endpoint, both of which conflict with this project's
offline-only requirement (see FRAMEWORK.md limitations). Installed-update
recency is used instead as a local, network-free proxy for patch hygiene.

Confirmed live: Win32_QuickFixEngineering.InstalledOn does NOT serialize as
a plain date string -- it arrives as a nested {"value": "/Date(ms)/",
"DateTime": "<readable string>"} object, so this collector selects the
DateTime sub-field explicitly via a calculated property rather than
guessing at the shape.

Automatic-update state: the legacy Group Policy key
(...\\WindowsUpdate\\Auto Update\\NoAutoUpdate) is checked first as a hard
override when present. Otherwise, this collector checks whether updates
are currently paused via HKLM\\SOFTWARE\\Microsoft\\WindowsUpdate\\UX\\Settings
\\PauseUpdatesExpiryTime -- the registry value written by the "Pause
updates" control in Settings > Windows Update. Confirmed live via direct
winreg access (not just PowerShell's Get-ItemProperty, which silently
returns a null placeholder for a requested-but-absent property and would
have been misleading here) that the parent key exists with real values
(ActiveHoursStart/End) while PauseUpdatesExpiryTime itself is absent when
updates are not paused -- a definite, current, verifiable signal, unlike
the legacy policy key this replaced as the primary source (see git
history / TESTING.md), whose absence could not distinguish "not managed
by policy" from "actually enabled."
"""

from __future__ import annotations

from datetime import datetime

from collectors.base import BaseCollector, CollectorContext
from utils import registry
from utils.helpers import as_list, days_since, parse_datetime
from utils.powershell import run_ps_capture

_AUTO_UPDATE_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"
_PAUSE_STATE_KEY = r"SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"


class UpdatesCollector(BaseCollector):
    collector_id = "updates"

    def _collect(self, ctx: CollectorContext) -> None:
        self._collect_service(ctx)
        self._collect_hotfixes(ctx)
        self._collect_update_pause_state(ctx)

    def _collect_service(self, ctx: CollectorContext) -> None:
        cap = run_ps_capture(
            "Get-Service -Name wuauserv -ErrorAction Stop | "
            "ForEach-Object { [PSCustomObject]@{ Status = $_.Status.ToString() } }"
        )
        if cap.ok and isinstance(cap.data, dict):
            ctx.set("wuauserv_running", cap.data.get("Status") == "Running")
        else:
            ctx.mark_error("wuauserv_running", cap.error or "unknown error querying wuauserv service")

    def _collect_hotfixes(self, ctx: CollectorContext) -> None:
        cap = run_ps_capture(
            "Get-CimInstance Win32_QuickFixEngineering -ErrorAction Stop | "
            "Select-Object HotFixID,@{Name='InstalledOn';Expression={$_.InstalledOn.DateTime}}"
        )
        if not cap.ok:
            ctx.mark_error("last_update_date", cap.error or "unknown error querying Win32_QuickFixEngineering")
            ctx.mark_error("days_since_last_update", cap.error or "unknown error querying Win32_QuickFixEngineering")
            return

        hotfixes = [h for h in as_list(cap.data) if isinstance(h, dict)]
        dates = [parse_datetime(h.get("InstalledOn")) for h in hotfixes]
        dates = [d for d in dates if d is not None]

        if not dates:
            ctx.mark_not_applicable("last_update_date", "No installed-update history reported by Win32_QuickFixEngineering")
            ctx.mark_not_applicable("days_since_last_update", "No installed-update history reported by Win32_QuickFixEngineering")
            return

        latest = max(dates)
        ctx.set("last_update_date", latest.isoformat())
        ctx.set("days_since_last_update", days_since(latest))

    def _collect_update_pause_state(self, ctx: CollectorContext) -> None:
        no_auto = registry.read_value("HKLM", _AUTO_UPDATE_KEY, "NoAutoUpdate")
        if no_auto.error:
            ctx.mark_error("updates_paused", no_auto.error)
            return
        if no_auto.exists and bool(no_auto.value):
            ctx.set("updates_paused", True)
            ctx.set("updates_paused_reason", "Automatic Updates disabled via Group Policy (NoAutoUpdate)")
            return

        pause_expiry = registry.read_value("HKLM", _PAUSE_STATE_KEY, "PauseUpdatesExpiryTime")
        if pause_expiry.error:
            ctx.mark_error("updates_paused", pause_expiry.error)
            return
        if not pause_expiry.exists or not pause_expiry.value:
            ctx.set("updates_paused", False)
            return

        expiry_dt = parse_datetime(str(pause_expiry.value))
        if expiry_dt is None:
            # A value is present but not in a recognized date format --
            # treat conservatively as still paused rather than ignoring it.
            ctx.set("updates_paused", True)
            ctx.set("updates_paused_reason", f"Updates paused (expiry unparsed: {pause_expiry.value!r})")
            return

        is_paused = expiry_dt > datetime.now()
        ctx.set("updates_paused", is_paused)
        if is_paused:
            ctx.set("updates_paused_reason", f"Updates paused until {expiry_dt.isoformat()}")
