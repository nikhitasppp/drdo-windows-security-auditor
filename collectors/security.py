"""
Windows Security collector (Microsoft Defender, SmartScreen, Security Center).

Defender state: Get-MpComputerStatus, the Defender PowerShell module's own
status API -- the authoritative source, confirmed to run without
elevation on a live Windows 11 host. Confirmed live that when Defender's
own antivirus engine is inactive (e.g. a third-party AV is the active
product), several properties legitimately come back null rather than
throwing an error; this collector treats that as "Defender itself is not
the active engine" rather than a collection failure, and cross-references
Security Center's registered-product list for context.

Last scan recency (defender_scan_age_days) is computed from whichever of
QuickScanEndTime / FullScanEndTime is more recent -- either a completed
quick or full scan counts as evidence the system was actually scanned.
Same null-when-inactive handling as the signature-age field above.

SmartScreen: checked via the per-user Explorer setting
(HKCU\\...\\Explorer\\SmartScreenEnabled) first, falling back to the
admin-enforced policy key. Confirmed live that neither exists on a stock
Windows 11 install with no explicit configuration -- in that case the
state is reported as UNABLE_TO_COLLECT rather than assumed, since Windows'
own default behavior in that scenario is not reliably exposed via the
registry.

Security Center product list: WMI root\\SecurityCenter2\\AntivirusProduct.
Its productState field is a legacy, undocumented bitmask; rather than
decode it unreliably, this collector reports registered product names
only (informational; see SEC-007) and leaves interpretation to the
reviewer.

Net Protector (NPAV): this environment's mandated third-party antivirus.
Only two things are checked, mirroring the reduced Defender check set:
whether it is running, and when it was last updated. "Running" is read
from the state of its main real-time-protection service, ZeroVProtect
(confirmed as NPAV's primary shield service by NPAV's own documentation
-- see FRAMEWORK.md). "Last updated" is read from the `timestamp` field
Windows Security Center records for whichever registered AntivirusProduct
entry matches Net Protector/NPAV -- there is no documented NPAV-specific
API or registry key for this, so Security Center's own record of the
product's last-reported state is the most reliable available signal. If
Net Protector is not installed (no ZeroVProtect service, or not present
in Security Center's product list), both are reported NOT_APPLICABLE,
never a false FAIL/UNABLE_TO_COLLECT.
"""

from __future__ import annotations

from collectors.base import BaseCollector, CollectorContext
from utils import registry
from utils.helpers import as_list, days_since, parse_datetime
from utils.powershell import run_ps_capture

_SMARTSCREEN_USER_KEY = r"Software\Microsoft\Windows\CurrentVersion\Explorer"
_SMARTSCREEN_POLICY_KEY = r"SOFTWARE\Policies\Microsoft\Windows\System"

# NPAV's main real-time-protection shield service (see module docstring).
_NETPROTECTOR_SERVICE = "ZeroVProtect"


class SecurityCollector(BaseCollector):
    collector_id = "security"

    def _collect(self, ctx: CollectorContext) -> None:
        self._collect_defender(ctx)
        self._collect_smartscreen(ctx)
        self._collect_security_center(ctx)
        self._collect_netprotector(ctx)

    def _collect_defender(self, ctx: CollectorContext) -> None:
        cap = run_ps_capture(
            "Get-MpComputerStatus -ErrorAction Stop | Select-Object "
            "RealTimeProtectionEnabled,AntivirusEnabled,MAPSReporting,"
            "AntivirusSignatureLastUpdated,IsTamperProtected,"
            "QuickScanEndTime,FullScanEndTime"
        )
        if not cap.ok:
            reason = cap.error or "unknown error querying Get-MpComputerStatus (Defender module may be unavailable)"
            for field in (
                "defender_realtime_protection_enabled", "defender_antivirus_enabled",
                "defender_cloud_protection_enabled", "defender_signature_age_days",
                "defender_signature_last_updated_date", "defender_last_scan_date",
                "defender_scan_age_days", "tamper_protection_enabled",
            ):
                ctx.mark_error(field, reason)
            return

        d = cap.data if isinstance(cap.data, dict) else {}

        ctx.set("defender_realtime_protection_enabled", bool(d.get("RealTimeProtectionEnabled")))
        antivirus_enabled = bool(d.get("AntivirusEnabled"))
        ctx.set("defender_antivirus_enabled", antivirus_enabled)

        # MAPSReporting is an enum: 0=Disabled, 1=Basic, 2=Advanced.
        maps_reporting = d.get("MAPSReporting")
        ctx.set("defender_cloud_protection_enabled", bool(maps_reporting) and int(maps_reporting) > 0)

        not_active_reason = "Microsoft Defender Antivirus is not the active engine on this system"

        sig_updated = parse_datetime(d.get("AntivirusSignatureLastUpdated"))
        if sig_updated is not None:
            ctx.set("defender_signature_age_days", days_since(sig_updated))
            ctx.set("defender_signature_last_updated_date", sig_updated.isoformat())
        elif not antivirus_enabled:
            ctx.mark_not_applicable("defender_signature_age_days", not_active_reason)
            ctx.mark_not_applicable("defender_signature_last_updated_date", not_active_reason)
        else:
            ctx.mark_error("defender_signature_age_days", "No signature update timestamp reported")
            ctx.mark_error("defender_signature_last_updated_date", "No signature update timestamp reported")

        # Report the more recent of the last completed quick/full scan --
        # either alone is a valid "system was scanned" signal.
        quick_scan = parse_datetime(d.get("QuickScanEndTime"))
        full_scan = parse_datetime(d.get("FullScanEndTime"))
        completed_scans = [t for t in (quick_scan, full_scan) if t is not None]
        last_scan = max(completed_scans) if completed_scans else None

        if last_scan is not None:
            ctx.set("defender_last_scan_date", last_scan.isoformat())
            ctx.set("defender_scan_age_days", days_since(last_scan))
        elif not antivirus_enabled:
            ctx.mark_not_applicable("defender_last_scan_date", not_active_reason)
            ctx.mark_not_applicable("defender_scan_age_days", not_active_reason)
        else:
            no_scan_reason = "No completed scan timestamp reported (Defender may not have completed a scan yet)"
            ctx.mark_error("defender_last_scan_date", no_scan_reason)
            ctx.mark_error("defender_scan_age_days", no_scan_reason)

        if "IsTamperProtected" in d:
            ctx.set("tamper_protection_enabled", bool(d.get("IsTamperProtected")))
        else:
            ctx.mark_not_applicable(
                "tamper_protection_enabled",
                "IsTamperProtected not reported by this Windows/Defender version",
            )

    def _collect_smartscreen(self, ctx: CollectorContext) -> None:
        user_setting = registry.read_value("HKCU", _SMARTSCREEN_USER_KEY, "SmartScreenEnabled")
        if user_setting.error:
            ctx.mark_error("smartscreen_enabled", user_setting.error)
            return
        if user_setting.exists:
            ctx.set("smartscreen_enabled", str(user_setting.value).strip().lower() not in ("off", "0"))
            return

        policy_setting = registry.read_value("HKLM", _SMARTSCREEN_POLICY_KEY, "EnableSmartScreen")
        if policy_setting.error:
            ctx.mark_error("smartscreen_enabled", policy_setting.error)
        elif policy_setting.exists:
            ctx.set("smartscreen_enabled", bool(policy_setting.value))
        else:
            # Neither a per-user override nor a policy override exists.
            # Confirmed live (including a byte-for-byte search of Edge's
            # own Preferences JSON) that Windows does not persist this
            # setting anywhere until a user or policy explicitly changes it
            # away from default. Microsoft documents SmartScreen ("Check
            # apps and files") as on by default on Windows 11, so absence
            # is reported as that documented default rather than as
            # UNABLE_TO_COLLECT -- explicitly a policy decision based on a
            # published default, not a live-verified read, and stated as
            # such here rather than presented as equivalent to a direct
            # registry read.
            ctx.set("smartscreen_enabled", True)

    def _collect_security_center(self, ctx: CollectorContext) -> None:
        cap = run_ps_capture(
            "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction Stop | "
            "Select-Object displayName"
        )
        if cap.ok:
            products = as_list(cap.data)
            ctx.set("registered_av_products", sorted({p.get("displayName") for p in products if isinstance(p, dict) and p.get("displayName")}))
        else:
            ctx.mark_error("registered_av_products", cap.error or "unknown error querying SecurityCenter2")

    def _collect_netprotector(self, ctx: CollectorContext) -> None:
        not_installed_reason = "Net Protector (NPAV) does not appear to be installed on this system"

        cap = run_ps_capture(
            f"Get-Service -Name {_NETPROTECTOR_SERVICE} -ErrorAction Stop | "
            "ForEach-Object { [PSCustomObject]@{ Status = $_.Status.ToString() } }"
        )
        if cap.ok and isinstance(cap.data, dict):
            ctx.set("netprotector_running", cap.data.get("Status") == "Running")
        elif cap.error and "cannot find any service" in cap.error.lower():
            ctx.mark_not_applicable("netprotector_running", not_installed_reason)
        else:
            ctx.mark_error(
                "netprotector_running",
                cap.error or f"unknown error querying {_NETPROTECTOR_SERVICE} service",
            )

        cap2 = run_ps_capture(
            "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction Stop | "
            "Where-Object { $_.displayName -match 'Net ?Protector|NPAV' } | "
            "Select-Object -First 1 displayName,timestamp"
        )
        if not cap2.ok:
            ctx.mark_error("netprotector_last_updated_date", cap2.error or "unknown error querying SecurityCenter2")
            return

        if not isinstance(cap2.data, dict) or not cap2.data.get("timestamp"):
            ctx.mark_not_applicable("netprotector_last_updated_date", not_installed_reason)
            return

        updated = parse_datetime(cap2.data.get("timestamp"))
        if updated is not None:
            ctx.set("netprotector_last_updated_date", updated.isoformat())
        else:
            ctx.mark_error(
                "netprotector_last_updated_date",
                f"Unrecognized timestamp format from Security Center: {cap2.data.get('timestamp')!r}",
            )
