"""
Remote Access collector.

All facts here are read directly from the registry via winreg (no
PowerShell needed) except WinRM's service state. Confirmed live on a
non-elevated Windows 11 host: fDenyTSConnections, UserAuthentication, and
fAllowToGetHelp are all readable without admin rights.
"""

from __future__ import annotations

from collectors.base import BaseCollector, CollectorContext
from utils import registry
from utils.powershell import run_ps_capture

_TERMINAL_SERVER_KEY = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
_RDP_TCP_KEY = r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
_REMOTE_ASSISTANCE_KEY = r"SYSTEM\CurrentControlSet\Control\Remote Assistance"


class RemoteAccessCollector(BaseCollector):
    collector_id = "remote_access"

    def _collect(self, ctx: CollectorContext) -> None:
        deny_ts = registry.read_value("HKLM", _TERMINAL_SERVER_KEY, "fDenyTSConnections")
        if deny_ts.error:
            ctx.mark_error("rdp_enabled", deny_ts.error)
        elif not deny_ts.exists:
            ctx.mark_error("rdp_enabled", "fDenyTSConnections registry value not found")
        else:
            ctx.set("rdp_enabled", int(deny_ts.value) == 0)

        nla = registry.read_value("HKLM", _RDP_TCP_KEY, "UserAuthentication")
        if nla.error:
            ctx.mark_error("rdp_nla_required", nla.error)
        elif not nla.exists:
            ctx.mark_error("rdp_nla_required", "UserAuthentication registry value not found")
        else:
            ctx.set("rdp_nla_required", int(nla.value) == 1)

        assistance = registry.read_value("HKLM", _REMOTE_ASSISTANCE_KEY, "fAllowToGetHelp")
        if assistance.error:
            ctx.mark_error("remote_assistance_enabled", assistance.error)
        elif not assistance.exists:
            ctx.set("remote_assistance_enabled", False)
        else:
            ctx.set("remote_assistance_enabled", int(assistance.value) == 1)

        cap = run_ps_capture(
            "Get-Service -Name WinRM -ErrorAction Stop | "
            "ForEach-Object { [PSCustomObject]@{ Status = $_.Status.ToString() } }"
        )
        if cap.ok and isinstance(cap.data, dict):
            ctx.set("winrm_running", cap.data.get("Status") == "Running")
        else:
            ctx.mark_error("winrm_running", cap.error or "unknown error querying WinRM service")
