"""
Device & Peripheral Security collector. The base inventory fields
(usb_storage_policy_state, usb_devices_connected, bluetooth_present,
webcam_access_setting, microphone_access_setting) are reported as INFO
(see FRAMEWORK.md): whether USB storage or camera/microphone access
should be restricted is organization-specific policy, not something a
general-purpose default can score as pass/fail without risking false
positives on ordinary consumer systems.

A second set of derived fields is scored as advisory (WARNING, not a
hard FAIL) rather than INFO: bluetooth_enabled (DEV-006),
usb_storage_devices_connected (DEV-007), webcam_access_setting (DEV-008)
and microphone_access_setting (DEV-005/DEV-009) being left enabled/
connected are each unambiguous -- if narrow -- attack surface, but none
of them are appropriate as a hard fail since many systems legitimately
need Bluetooth, USB storage, a camera or a microphone. bluetooth_enabled
is only evaluated when bluetooth_present confirms a radio actually
exists, via DEV-006's depends_on. usb_storage_devices_connected is a
filtered subset of usb_devices_connected (mass-storage entries only) so
the advisory doesn't fire on every machine just for having a USB hub or
keyboard attached.
"""

from __future__ import annotations

from collectors.base import BaseCollector, CollectorContext
from utils import registry
from utils.helpers import as_list, parse_datetime
from utils.powershell import run_ps_capture

_USBSTOR_START_LABELS = {0: "Boot", 1: "System", 2: "Automatic", 3: "Manual", 4: "Disabled"}


class DevicesCollector(BaseCollector):
    collector_id = "devices"

    def _collect(self, ctx: CollectorContext) -> None:
        self._collect_usb_storage_policy(ctx)
        self._collect_pnp_devices(ctx)
        self._collect_usb_storage_history(ctx)
        self._collect_capability_access(ctx, "webcam", "webcam_access_setting")
        self._collect_capability_access(ctx, "microphone", "microphone_access_setting")

    def _collect_usb_storage_policy(self, ctx: CollectorContext) -> None:
        result = registry.read_value("HKLM", r"SYSTEM\CurrentControlSet\Services\USBSTOR", "Start")
        if result.error:
            ctx.mark_error("usb_storage_policy_state", result.error)
        elif not result.exists:
            ctx.mark_error("usb_storage_policy_state", "USBSTOR Start registry value not found")
        else:
            ctx.set("usb_storage_policy_state", _USBSTOR_START_LABELS.get(int(result.value), str(result.value)))

    def _collect_pnp_devices(self, ctx: CollectorContext) -> None:
        usb_cap = run_ps_capture(
            "Get-PnpDevice -Class USB -ErrorAction Stop | Select-Object FriendlyName,Status"
        )
        if usb_cap.ok:
            usb_devices = [d for d in as_list(usb_cap.data) if isinstance(d, dict)]
            ctx.set("usb_devices_connected", usb_devices)
            storage_devices = [d for d in usb_devices if "mass storage" in str(d.get("FriendlyName", "")).lower()]
            ctx.set("usb_storage_devices_connected", storage_devices)
        else:
            reason = usb_cap.error or "unknown error querying Get-PnpDevice -Class USB"
            ctx.mark_error("usb_devices_connected", reason)
            ctx.mark_error("usb_storage_devices_connected", reason)

        bt_cap = run_ps_capture(
            "Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue | Select-Object FriendlyName,Status"
        )
        if bt_cap.ok:
            bt_devices = [d for d in as_list(bt_cap.data) if isinstance(d, dict)]
            present = len(bt_devices) > 0
            ctx.set("bluetooth_present", present)
            if present:
                ctx.set("bluetooth_enabled", any(d.get("Status") == "OK" for d in bt_devices))
            else:
                ctx.mark_not_applicable("bluetooth_enabled", "No Bluetooth adapter is present on this system")
        else:
            reason = bt_cap.error or "unknown error querying Get-PnpDevice -Class Bluetooth"
            ctx.mark_error("bluetooth_present", reason)
            ctx.mark_error("bluetooth_enabled", reason)

    def _collect_usb_storage_history(self, ctx: CollectorContext) -> None:
        # -PresentOnly:$false includes USB storage devices that were
        # plugged in previously and later removed, not just currently
        # attached ones -- that's the point of this check (a history of
        # what's ever touched the system, not just what's connected now).
        # Confirmed live: Get-PnpDeviceProperty's InstallDate/
        # LastArrivalDate come back in ConvertTo-Json's "/Date(ms)/" form,
        # already handled by utils.helpers.parse_datetime.
        cap = run_ps_capture(
            "Get-PnpDevice -PresentOnly:$false -ErrorAction Stop | "
            "Where-Object { $_.InstanceId -like 'USBSTOR\\*' } | "
            "ForEach-Object { $iid = $_.InstanceId; [PSCustomObject]@{ "
            "FriendlyName = $_.FriendlyName; "
            "SerialNumber = ($iid -split '\\\\')[-1]; "
            "Manufacturer = (Get-PnpDeviceProperty -InstanceId $iid -KeyName 'DEVPKEY_Device_Manufacturer' "
            "-ErrorAction SilentlyContinue).Data; "
            "FirstInstalled = (Get-PnpDeviceProperty -InstanceId $iid -KeyName 'DEVPKEY_Device_InstallDate' "
            "-ErrorAction SilentlyContinue).Data; "
            "LastArrival = (Get-PnpDeviceProperty -InstanceId $iid -KeyName 'DEVPKEY_Device_LastArrivalDate' "
            "-ErrorAction SilentlyContinue).Data } }"
        )
        if not cap.ok:
            ctx.mark_error("usb_storage_history", cap.error or "unknown error querying Get-PnpDevice")
            return

        history = []
        for d in as_list(cap.data):
            if not isinstance(d, dict):
                continue
            first_used = parse_datetime(d.get("FirstInstalled"))
            last_used = parse_datetime(d.get("LastArrival"))
            history.append({
                "friendly_name": d.get("FriendlyName"),
                "serial_number": d.get("SerialNumber"),
                "manufacturer": d.get("Manufacturer"),
                "first_used": first_used.strftime("%Y-%m-%d") if first_used else None,
                "last_used": last_used.strftime("%Y-%m-%d") if last_used else None,
            })
        ctx.set("usb_storage_history", history)

    def _collect_capability_access(self, ctx: CollectorContext, capability: str, field: str) -> None:
        key = rf"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\{capability}"
        result = registry.read_value("HKCU", key, "Value")
        if result.error:
            ctx.mark_error(field, result.error)
        elif not result.exists:
            ctx.set(field, "NotConfigured")
        else:
            ctx.set(field, str(result.value))
