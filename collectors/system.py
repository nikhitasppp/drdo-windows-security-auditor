"""
System & Hardware collector.

Sources (see FRAMEWORK.md for the full justification):
  - Win32_OperatingSystem / Win32_ComputerSystem / Win32_Processor (CIM) for
    OS, host, and CPU facts -- the standard, stable source for these.
  - Get-Volume for storage.
  - Registry HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State
    (key presence only) as a UEFI-vs-legacy-BIOS signal.
  - Confirm-SecureBootUEFI for the actual Secure Boot enabled/disabled state;
    this cmdlet throws on legacy BIOS systems, which is treated as
    NOT_APPLICABLE rather than an error.
  - Get-Tpm for TPM state. Confirmed live: on a non-elevated Windows 11
    session, Get-Tpm does NOT throw a catchable exception when only
    specific properties are selected -- it silently returns those
    properties as null instead. This collector cannot tell "no TPM chip"
    apart from "insufficient privilege" in that case, so it reports
    UNABLE_TO_COLLECT rather than guessing when not elevated.
  - Identity fields (ip_address/mac_address/network_interface): sourced
    from Get-NetIPConfiguration filtered to the interface with a default
    gateway, not an unfiltered adapter list -- confirmed live that an
    unfiltered query can return a VirtualBox/VPN host-only adapter's
    address instead of the actual LAN/Wi-Fi address.
  - machine: $env:PROCESSOR_ARCHITECTURE (e.g. "AMD64"), the conventional
    machine-architecture identifier, distinct from OSArchitecture's
    "64-bit" wording used by the `architecture` field.
  - connectivity: Get-NetConnectionProfile's active profile name.
  - wifi_interface: same Get-NetAdapter / PhysicalMediaType filter as
    network.py's wireless_adapter_enabled, kept as a separate self-
    contained query here since collectors cannot depend on each other's
    output (each is evaluated independently).
"""

from __future__ import annotations

import os
from datetime import datetime

from collectors.base import BaseCollector, CollectorContext
from utils import registry
from utils.helpers import as_list, bytes_to_gb, parse_datetime, safe_int
from utils.powershell import run_ps_capture

_SECUREBOOT_STATE_KEY = r"SYSTEM\CurrentControlSet\Control\SecureBoot\State"

# SoftwareLicensingProduct.LicenseStatus values, per Microsoft's
# documented enum -- same source `slmgr.vbs /dli` reads from.
_LICENSE_STATUS_LABELS = {
    0: "Unlicensed",
    1: "Licensed",
    2: "Out-of-Box Grace Period",
    3: "Out-of-Tolerance Grace Period",
    4: "Non-Genuine Grace Period",
    5: "Notification",
    6: "Extended Grace Period",
}
# The Windows OS edition's Application ID in the software licensing
# service -- filters out unrelated licensed products (e.g. Office) that
# also register SoftwareLicensingProduct entries.
_WINDOWS_LICENSING_APP_ID = "55c92734-d682-4d71-983e-d6ec3f16059f"


class SystemCollector(BaseCollector):
    collector_id = "system"

    def _collect(self, ctx: CollectorContext) -> None:
        self._collect_os_and_host(ctx)
        self._collect_identity(ctx)
        self._collect_cpu(ctx)
        self._collect_volumes(ctx)
        self._collect_firmware(ctx)
        self._collect_tpm(ctx)
        self._collect_license_status(ctx)

    def _collect_os_and_host(self, ctx: CollectorContext) -> None:
        os_cap = run_ps_capture(
            "Get-CimInstance Win32_OperatingSystem -ErrorAction Stop | "
            "Select-Object Caption,Version,BuildNumber,OSArchitecture,LastBootUpTime,"
            "WindowsDirectory,SystemDirectory,InstallDate,CSDVersion,SerialNumber"
        )
        if os_cap.ok and isinstance(os_cap.data, dict):
            d = os_cap.data
            caption = d.get("Caption") or ""
            ctx.set("os_caption", d.get("Caption"))
            ctx.set("os_version", d.get("Version"))
            ctx.set("os_build", d.get("BuildNumber"))
            ctx.set("architecture", d.get("OSArchitecture"))
            ctx.set("windows_directory", d.get("WindowsDirectory"))
            ctx.set("system_directory", d.get("SystemDirectory"))
            # Modern Windows 10/11 has no service packs; CSDVersion is
            # legitimately empty in that case (not a collection failure) --
            # reported as "None" rather than left blank, matching the
            # convention Windows' own System Information / systeminfo use.
            ctx.set("service_pack", d.get("CSDVersion") or "None")
            ctx.set("windows_product_id", d.get("SerialNumber"))
            # Caption reads e.g. "Microsoft Windows 11 Home" / "Microsoft
            # Windows 10 Pro" -- both report Version "10.0.x", so Caption
            # (not Version) is what actually distinguishes 10 from 11, and
            # from anything unsupported (7/8/Server/etc).
            ctx.set("os_supported_version", ("Windows 10" in caption) or ("Windows 11" in caption))
            boot_time = parse_datetime(d.get("LastBootUpTime"))
            if boot_time:
                ctx.set("uptime_hours", round((datetime.now() - boot_time).total_seconds() / 3600, 1))
            else:
                ctx.mark_error("uptime_hours", "could not parse LastBootUpTime")
            install_time = parse_datetime(d.get("InstallDate"))
            ctx.set("os_install_date", install_time.strftime("%Y-%m-%d") if install_time else None)
        else:
            reason = os_cap.error or "unknown error querying Win32_OperatingSystem"
            for field in ("os_caption", "os_version", "os_build", "architecture", "uptime_hours",
                          "windows_directory", "system_directory", "os_install_date", "service_pack",
                          "windows_product_id", "os_supported_version"):
                ctx.mark_error(field, reason)

        host_cap = run_ps_capture(
            "Get-CimInstance Win32_ComputerSystem -ErrorAction Stop | "
            "Select-Object Name,Domain,PartOfDomain,TotalPhysicalMemory"
        )
        if host_cap.ok and isinstance(host_cap.data, dict):
            d = host_cap.data
            ctx.set("computer_name", d.get("Name"))
            ctx.set("domain_or_workgroup", d.get("Domain"))
            ctx.set("part_of_domain", bool(d.get("PartOfDomain")))
            ctx.set("ram_total_gb", bytes_to_gb(d.get("TotalPhysicalMemory")))
        else:
            reason = host_cap.error or "unknown error querying Win32_ComputerSystem"
            for field in ("computer_name", "domain_or_workgroup", "part_of_domain", "ram_total_gb"):
                ctx.mark_error(field, reason)

    def _collect_identity(self, ctx: CollectorContext) -> None:
        # Filtered to the interface with a default gateway so this reports
        # the real primary adapter's address, not whichever adapter happens
        # to be enumerated first -- confirmed live that an unfiltered query
        # can return a VirtualBox/VPN host-only adapter's address instead
        # of the actual LAN/Wi-Fi address.
        net_cap = run_ps_capture(
            "Get-NetIPConfiguration -ErrorAction Stop | Where-Object { $_.IPv4DefaultGateway } | "
            "Select-Object -First 1 | ForEach-Object { [PSCustomObject]@{ "
            "IPAddress = $_.IPv4Address.IPAddress; MacAddress = $_.NetAdapter.MacAddress; "
            "InterfaceAlias = $_.InterfaceAlias } }"
        )
        if net_cap.ok:
            d = net_cap.data if isinstance(net_cap.data, dict) else {}
            ctx.set("ip_address", d.get("IPAddress"))
            ctx.set("mac_address", d.get("MacAddress"))
            ctx.set("network_interface", d.get("InterfaceAlias"))
        else:
            reason = net_cap.error or "unknown error querying Get-NetIPConfiguration"
            ctx.mark_error("ip_address", reason)
            ctx.mark_error("mac_address", reason)
            ctx.mark_error("network_interface", reason)

        # $env:PROCESSOR_ARCHITECTURE (e.g. "AMD64") -- the conventional
        # "machine" architecture identifier (matches Python's own
        # platform.machine() on Windows), distinct from OSArchitecture's
        # "64-bit" wording used by the `architecture` field above.
        ctx.set("machine", os.environ.get("PROCESSOR_ARCHITECTURE"))

        profile_cap = run_ps_capture(
            "Get-NetConnectionProfile -ErrorAction Stop | Select-Object -First 1 -ExpandProperty Name"
        )
        if profile_cap.ok:
            ctx.set("connectivity", f"{profile_cap.data} Connected" if profile_cap.data else "Not Connected")
        else:
            ctx.mark_error("connectivity", profile_cap.error or "unknown error querying Get-NetConnectionProfile")

        wifi_cap = run_ps_capture(
            "Get-NetAdapter -ErrorAction Stop | Where-Object { $_.PhysicalMediaType -eq 'Native 802.11' } | "
            "Select-Object -First 1 -ExpandProperty Name"
        )
        if wifi_cap.ok:
            ctx.set("wifi_interface", wifi_cap.data or "There is no wireless interface on the system.")
        else:
            ctx.mark_error("wifi_interface", wifi_cap.error or "unknown error querying Get-NetAdapter")

        bios_cap = run_ps_capture(
            "Get-CimInstance Win32_BIOS -ErrorAction Stop | Select-Object SerialNumber,SMBIOSBIOSVersion"
        )
        if bios_cap.ok and isinstance(bios_cap.data, dict):
            d = bios_cap.data
            ctx.set("system_serial_number", d.get("SerialNumber"))
            ctx.set("bios_version", d.get("SMBIOSBIOSVersion"))
        else:
            reason = bios_cap.error or "unknown error querying Win32_BIOS"
            ctx.mark_error("system_serial_number", reason)
            ctx.mark_error("bios_version", reason)

    def _collect_cpu(self, ctx: CollectorContext) -> None:
        cap = run_ps_capture(
            "Get-CimInstance Win32_Processor -ErrorAction Stop | "
            "Select-Object -First 1 Name,NumberOfCores,NumberOfLogicalProcessors"
        )
        if cap.ok and isinstance(cap.data, dict):
            d = cap.data
            ctx.set("cpu_name", d.get("Name"))
            ctx.set("cpu_cores", safe_int(d.get("NumberOfCores")))
            ctx.set("cpu_logical_processors", safe_int(d.get("NumberOfLogicalProcessors")))
        else:
            reason = cap.error or "unknown error querying Win32_Processor"
            ctx.mark_error("cpu_name", reason)

    def _collect_volumes(self, ctx: CollectorContext) -> None:
        cap = run_ps_capture(
            "Get-Volume -ErrorAction Stop | Where-Object { $_.DriveLetter } | "
            "Select-Object DriveLetter,"
            "@{Name='SizeGB';Expression={[math]::Round($_.Size/1GB,1)}},"
            "@{Name='FreeGB';Expression={[math]::Round($_.SizeRemaining/1GB,1)}}"
        )
        if cap.ok:
            volumes = as_list(cap.data)
            ctx.set("volumes", [
                {
                    "drive": f"{v.get('DriveLetter')}:",
                    "size_gb": v.get("SizeGB"),
                    "free_gb": v.get("FreeGB"),
                }
                for v in volumes if isinstance(v, dict)
            ])
        else:
            ctx.mark_error("volumes", cap.error or "unknown error querying Get-Volume")

    def _collect_firmware(self, ctx: CollectorContext) -> None:
        secureboot_key = registry.key_exists("HKLM", _SECUREBOOT_STATE_KEY)
        if secureboot_key.error:
            ctx.mark_error("firmware_type", secureboot_key.error)
        else:
            ctx.set("firmware_type", "UEFI" if secureboot_key.exists else "Legacy BIOS")

        sb_cap = run_ps_capture("Confirm-SecureBootUEFI -ErrorAction Stop")
        if sb_cap.ok:
            ctx.set("secure_boot_enabled", bool(sb_cap.data))
        else:
            err = (sb_cap.error or "").lower()
            if "not supported" in err or "cmdlet not supported" in err or not secureboot_key.exists:
                ctx.mark_not_applicable(
                    "secure_boot_enabled",
                    "System does not boot via UEFI (legacy BIOS), so Secure Boot does not apply.",
                )
            else:
                ctx.mark_error("secure_boot_enabled", sb_cap.error or "unknown error checking Secure Boot state")

    def _collect_tpm(self, ctx: CollectorContext) -> None:
        cap = run_ps_capture("Get-Tpm | Select-Object TpmPresent,TpmReady,TpmEnabled")
        if not cap.ok:
            ctx.mark_error("tpm_ready", cap.error or "unknown error querying Get-Tpm")
            return

        d = cap.data if isinstance(cap.data, dict) else {}
        tpm_present = d.get("TpmPresent")
        tpm_ready = d.get("TpmReady")

        if tpm_present is None and tpm_ready is None:
            # Confirmed live: Get-Tpm returns all-null properties (without
            # throwing) when not elevated. We cannot distinguish "no TPM"
            # from "insufficient privilege" in that case.
            if not self.admin_available:
                ctx.mark_error("tpm_ready", "Administrator privileges required to read TPM state")
            else:
                ctx.mark_not_applicable("tpm_ready", "No TPM device detected on this system")
            return

        ctx.set("tpm_present", bool(tpm_present))
        if tpm_present is False:
            ctx.mark_not_applicable("tpm_ready", "No TPM device is present on this system")
        else:
            ctx.set("tpm_ready", bool(tpm_ready))

    def _collect_license_status(self, ctx: CollectorContext) -> None:
        # Same technique `slmgr.vbs /dli` uses: the licensed OS edition is
        # the SoftwareLicensingProduct entry for Windows' own Application
        # ID that actually has a partial product key installed (other
        # matching entries exist but are inactive).
        cap = run_ps_capture(
            "Get-CimInstance SoftwareLicensingProduct -ErrorAction Stop -Filter "
            f"\"ApplicationID='{_WINDOWS_LICENSING_APP_ID}' and PartialProductKey is not null\" | "
            "Select-Object -First 1 LicenseStatus"
        )
        if not cap.ok:
            ctx.mark_error("windows_license_status", cap.error or "unknown error querying SoftwareLicensingProduct")
            return

        d = cap.data if isinstance(cap.data, dict) else {}
        status = safe_int(d.get("LicenseStatus"))
        if status is None:
            ctx.mark_error("windows_license_status", "no licensed Windows product entry found")
        else:
            ctx.set("windows_license_status", _LICENSE_STATUS_LABELS.get(status, f"Unknown ({status})"))
