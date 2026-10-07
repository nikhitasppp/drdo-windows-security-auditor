"""
Services collector.

Sources: Win32_Service (CIM) for mpssvc/WinDefend, whose State property is
a plain string ("Running"/"Stopped") with no enum-casting ambiguity
(confirmed live) -- and Get-Service for the remainder, whose Status
property IS a .NET enum and is explicitly cast to string inside the
PowerShell expression to avoid relying on undocumented integer values
(confirmed live: Get-Service serializes Status/StartType as bare integers
unless cast).
"""

from __future__ import annotations

from collectors.base import BaseCollector, CollectorContext
from utils.helpers import as_list
from utils.powershell import run_ps_capture


class ServicesCollector(BaseCollector):
    collector_id = "services"

    def _collect(self, ctx: CollectorContext) -> None:
        self._collect_security_services(ctx)
        self._collect_service_state("RemoteRegistry", "remote_registry_running", ctx)
        self._collect_service_state("Spooler", "print_spooler_running", ctx)
        self._collect_auto_start_services(ctx)

    def _collect_security_services(self, ctx: CollectorContext) -> None:
        cap = run_ps_capture(
            "Get-CimInstance Win32_Service -Filter \"Name='mpssvc' OR Name='WinDefend'\" -ErrorAction Stop | "
            "Select-Object Name,State"
        )
        if not cap.ok:
            reason = cap.error or "unknown error querying Win32_Service"
            ctx.mark_error("firewall_service_running", reason)
            ctx.mark_error("defender_service_running", reason)
            return

        states = {s.get("Name"): s.get("State") for s in as_list(cap.data) if isinstance(s, dict)}

        if "mpssvc" in states:
            ctx.set("firewall_service_running", states["mpssvc"] == "Running")
        else:
            ctx.mark_error("firewall_service_running", "mpssvc service not found")

        if "WinDefend" in states:
            ctx.set("defender_service_running", states["WinDefend"] == "Running")
        else:
            ctx.mark_error("defender_service_running", "WinDefend service not found")

    def _collect_service_state(self, service_name: str, field: str, ctx: CollectorContext) -> None:
        cap = run_ps_capture(
            f"Get-Service -Name {service_name} -ErrorAction Stop | "
            "ForEach-Object { [PSCustomObject]@{ Status = $_.Status.ToString() } }"
        )
        if cap.ok and isinstance(cap.data, dict):
            ctx.set(field, cap.data.get("Status") == "Running")
        else:
            ctx.mark_error(field, cap.error or f"unknown error querying {service_name} service")

    def _collect_auto_start_services(self, ctx: CollectorContext) -> None:
        cap = run_ps_capture(
            "Get-CimInstance Win32_Service -Filter \"StartMode='Auto'\" -ErrorAction Stop | "
            "Select-Object Name"
        )
        if cap.ok:
            ctx.set("auto_start_services", [s.get("Name") for s in as_list(cap.data) if isinstance(s, dict)])
        else:
            ctx.mark_error("auto_start_services", cap.error or "unknown error querying Win32_Service")
