"""
Network configuration collector.

Sources: Get-NetTCPConnection (NetTCPIP module) for listening ports,
Get-NetConnectionProfile for the network category Windows has assigned
each adapter, Get-DnsClientServerAddress for configured DNS servers -- all
confirmed to run without elevation on a live Windows 11 host. Proxy state
is read directly from the per-user registry value via winreg rather than
a PowerShell cmdlet, since there is no dedicated read cmdlet for it.

Wireless adapter state: Get-NetAdapter (NetAdapter module), filtered to
PhysicalMediaType -eq 'Native 802.11' -- confirmed live that this is the
exact string Windows reports for a Wi-Fi adapter (not the more obvious
'802.11', which matches nothing and would silently make this check
always report "no wireless adapter present" on every real system).

Established connections (Get-NetTCPConnection -State Established) and
UDP endpoints (Get-NetUDPEndpoint) are reported as INFO inventories,
alongside a new listening_ports field (all listening TCP ports, not just
the high-risk subset already scored by NET-004) -- these are descriptive
network-activity snapshots, not something with a universal pass/fail.

established_connections_count, udp_endpoints_count, and
listening_ports_count are the exceptions, per explicit instruction:
genuine scored PASS/FAIL (NET-012, > 5 -> FAIL; NET-013, > 15 -> FAIL;
NET-014, > 6 -> FAIL), not advisories -- unlike the other counts, "too
many established connections/UDP endpoints/open ports" does have a
fairly universal expectation for an ordinary client workstation.
listening_ports_count counts distinct port numbers, not raw listener
entries, since the same port commonly listens on both an IPv4 and IPv6
address.
"""

from __future__ import annotations

from collectors.base import BaseCollector, CollectorContext
from utils import registry
from utils.helpers import as_list
from utils.powershell import run_ps_capture

# Legacy/plaintext or historically-abused services that should not be
# listening on a hardened Windows 11 workstation. RDP (3389) and SMB/RPC
# (135/139/445) are deliberately excluded here: RDP has its own dedicated
# check (RDP-001), and SMB/RPC are expected to be present on stock Windows
# and would otherwise make this check noisy to the point of being ignored.
_HIGH_RISK_PORTS = {
    21: "FTP",
    23: "Telnet",
    69: "TFTP",
    512: "rexec",
    513: "rlogin",
    514: "rsh",
    5900: "VNC",
}

_PROXY_SETTINGS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"


class NetworkCollector(BaseCollector):
    collector_id = "network"

    def _collect(self, ctx: CollectorContext) -> None:
        self._collect_listening_ports(ctx)
        self._collect_established_connections(ctx)
        self._collect_udp_endpoints(ctx)
        self._collect_connection_profiles(ctx)
        self._collect_dns(ctx)
        self._collect_proxy(ctx)
        self._collect_wireless(ctx)

    def _collect_listening_ports(self, ctx: CollectorContext) -> None:
        cap = run_ps_capture(
            "Get-NetTCPConnection -State Listen -ErrorAction Stop | Select-Object LocalPort,OwningProcess"
        )
        if not cap.ok:
            reason = cap.error or "unknown error querying Get-NetTCPConnection"
            ctx.mark_error("high_risk_ports_listening", reason)
            ctx.mark_error("listening_ports", reason)
            ctx.mark_error("listening_ports_count", reason)
            return

        entries = [p for p in as_list(cap.data) if isinstance(p, dict)]
        listening_ports = {e.get("LocalPort") for e in entries}
        ctx.set("high_risk_ports_listening", [
            {"port": port, "service": name}
            for port, name in _HIGH_RISK_PORTS.items()
            if port in listening_ports
        ])
        ctx.set("listening_ports", [
            {"port": e.get("LocalPort"), "process_id": e.get("OwningProcess")} for e in entries
        ])
        # Distinct port numbers, not raw listener entries -- the same port
        # commonly listens on both an IPv4 and IPv6 address, which would
        # otherwise double-count it.
        ctx.set("listening_ports_count", len(listening_ports))

    def _collect_established_connections(self, ctx: CollectorContext) -> None:
        cap = run_ps_capture(
            "Get-NetTCPConnection -State Established -ErrorAction Stop | "
            "Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess"
        )
        if not cap.ok:
            reason = cap.error or "unknown error querying Get-NetTCPConnection"
            ctx.mark_error("established_connections", reason)
            ctx.mark_error("established_connections_count", reason)
            return

        connections = [
            {
                "local_address": c.get("LocalAddress"),
                "local_port": c.get("LocalPort"),
                "remote_address": c.get("RemoteAddress"),
                "remote_port": c.get("RemotePort"),
                "process_id": c.get("OwningProcess"),
            }
            for c in as_list(cap.data) if isinstance(c, dict)
        ]
        ctx.set("established_connections", connections)
        ctx.set("established_connections_count", len(connections))

    def _collect_udp_endpoints(self, ctx: CollectorContext) -> None:
        cap = run_ps_capture(
            "Get-NetUDPEndpoint -ErrorAction Stop | Select-Object LocalAddress,LocalPort"
        )
        if not cap.ok:
            reason = cap.error or "unknown error querying Get-NetUDPEndpoint"
            ctx.mark_error("udp_endpoints", reason)
            ctx.mark_error("udp_endpoints_count", reason)
            return

        endpoints = [
            {"local_address": e.get("LocalAddress"), "local_port": e.get("LocalPort")}
            for e in as_list(cap.data) if isinstance(e, dict)
        ]
        ctx.set("udp_endpoints", endpoints)
        ctx.set("udp_endpoints_count", len(endpoints))

    def _collect_connection_profiles(self, ctx: CollectorContext) -> None:
        cap = run_ps_capture(
            "Get-NetConnectionProfile -ErrorAction Stop | "
            "ForEach-Object { [PSCustomObject]@{ Name = $_.Name; NetworkCategory = $_.NetworkCategory.ToString() } }"
        )
        if cap.ok:
            ctx.set("connection_profiles", [p for p in as_list(cap.data) if isinstance(p, dict)])
        else:
            ctx.mark_error("connection_profiles", cap.error or "unknown error querying Get-NetConnectionProfile")

    def _collect_dns(self, ctx: CollectorContext) -> None:
        cap = run_ps_capture(
            "Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop | "
            "Where-Object { $_.ServerAddresses.Count -gt 0 } | "
            "Select-Object InterfaceAlias,ServerAddresses"
        )
        if cap.ok:
            ctx.set("dns_servers", [d for d in as_list(cap.data) if isinstance(d, dict)])
        else:
            ctx.mark_error("dns_servers", cap.error or "unknown error querying Get-DnsClientServerAddress")

    def _collect_proxy(self, ctx: CollectorContext) -> None:
        result = registry.read_value("HKCU", _PROXY_SETTINGS_KEY, "ProxyEnable")
        if result.error:
            ctx.mark_error("proxy_enabled", result.error)
        elif not result.exists:
            ctx.set("proxy_enabled", False)
        else:
            ctx.set("proxy_enabled", bool(result.value))

    def _collect_wireless(self, ctx: CollectorContext) -> None:
        cap = run_ps_capture(
            "Get-NetAdapter -ErrorAction Stop | Where-Object { $_.PhysicalMediaType -eq 'Native 802.11' } | "
            "Select-Object Name,InterfaceDescription,@{Name='Status';Expression={$_.Status.ToString()}}"
        )
        if not cap.ok:
            reason = cap.error or "unknown error querying Get-NetAdapter"
            ctx.mark_error("wireless_interfaces", reason)
            ctx.mark_error("wireless_adapter_enabled", reason)
            return

        adapters = [a for a in as_list(cap.data) if isinstance(a, dict)]
        ctx.set("wireless_interfaces", adapters)
        if not adapters:
            ctx.mark_not_applicable(
                "wireless_adapter_enabled",
                "No wireless (802.11) network adapter is present on this system",
            )
            return

        ctx.set("wireless_adapter_enabled", any(a.get("Status") == "Up" for a in adapters))
