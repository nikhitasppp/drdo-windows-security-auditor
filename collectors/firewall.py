"""
Firewall profile collector.

Source: Get-NetFirewallProfile (NetSecurity module) -- the same API the
Windows Defender Firewall control panel and `netsh advfirewall` read from,
returning structured objects rather than parsed console text. Confirmed to
run without elevation on a live Windows 11 host. The cmdlet's Enabled
property is a CIM boolean-like enum that serializes as an ambiguous 1/0
through ConvertTo-Json unless explicitly cast; this collector casts it to
[bool] inside the PowerShell expression itself to avoid guessing at the
Python side.
"""

from __future__ import annotations

from collectors.base import BaseCollector, CollectorContext
from utils.helpers import as_list
from utils.powershell import run_ps_capture

_PROFILE_FIELD = {
    "Domain": "domain_profile_enabled",
    "Private": "private_profile_enabled",
    "Public": "public_profile_enabled",
}


class FirewallCollector(BaseCollector):
    collector_id = "firewall"

    def _collect(self, ctx: CollectorContext) -> None:
        cap = run_ps_capture(
            "Get-NetFirewallProfile -ErrorAction Stop | "
            "ForEach-Object { [PSCustomObject]@{ Name = $_.Name; Enabled = [bool]$_.Enabled } }"
        )
        if not cap.ok:
            reason = cap.error or "unknown error querying Get-NetFirewallProfile"
            for field in _PROFILE_FIELD.values():
                ctx.mark_error(field, reason)
            return

        profiles = {p.get("Name"): p.get("Enabled") for p in as_list(cap.data) if isinstance(p, dict)}
        for profile_name, field in _PROFILE_FIELD.items():
            if profile_name in profiles:
                ctx.set(field, bool(profiles[profile_name]))
            else:
                ctx.mark_error(field, f"{profile_name} firewall profile not reported by Get-NetFirewallProfile")
