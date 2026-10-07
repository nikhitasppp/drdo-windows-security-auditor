"""
Data & Storage Security collector.

BitLocker: Get-BitLockerVolume (BitLocker module). Confirmed live that this
throws "Access denied" without elevation on a non-admin Windows 11
session, so BitLocker facts are UNABLE_TO_COLLECT on an unprivileged run.
Confirmed live on an elevated session (2026-08-19) that the success path
also works: the development machine's OS drive was correctly reported as
unprotected.

SMB shares: Get-SmbShare, confirmed to run without elevation; built-in
administrative shares (ADMIN$, IPC$, and per-drive `<letter>$` shares)
are excluded since their presence is normal Windows behavior, not a
misconfiguration. non_default_smb_shares is used by three rules:
STG-004 (any share present -> FAIL, the strict existing check),
STG-006 (the plain list, INFO), and STG-007 (a genuine scored
PASS/FAIL on non_default_smb_shares_count, > 3 -> FAIL, per explicit
instruction).

System directory ACLs: Get-Acl on C:\\Windows. This is a best-effort
heuristic against a fixed allow-list of trusted principals -- correctly
modeling NTFS permission inheritance and effective access in general is
out of scope for this check; it flags only direct, explicit Allow ACEs
granting write-class rights to an identity outside the allow-list.
"""

from __future__ import annotations

from collectors.base import BaseCollector, CollectorContext
from utils.helpers import as_list
from utils.powershell import run_ps_capture

_TRUSTED_ACL_IDENTITIES = {
    "NT AUTHORITY\\SYSTEM",
    "BUILTIN\\Administrators",
    "NT SERVICE\\TrustedInstaller",
    "CREATOR OWNER",
    "APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES",
    "APPLICATION PACKAGE AUTHORITY\\ALL RESTRICTED APPLICATION PACKAGES",
}
_WRITE_RIGHTS_MARKERS = ("Write", "Modify", "FullControl")

_DEFAULT_ADMIN_SHARES = {"ADMIN$", "IPC$"}


class StorageCollector(BaseCollector):
    collector_id = "storage"

    def _collect(self, ctx: CollectorContext) -> None:
        self._collect_bitlocker(ctx)
        self._collect_smb_shares(ctx)
        self._collect_system_dir_acl(ctx)

    def _collect_bitlocker(self, ctx: CollectorContext) -> None:
        cap = run_ps_capture(
            "Get-BitLockerVolume -ErrorAction Stop | "
            "ForEach-Object { [PSCustomObject]@{ MountPoint = $_.MountPoint; "
            "ProtectionStatus = $_.ProtectionStatus.ToString(); VolumeType = $_.VolumeType.ToString() } }"
        )
        if not cap.ok:
            reason = cap.error or "unknown error querying Get-BitLockerVolume"
            for field in ("bitlocker_os_drive_protected", "bitlocker_fixed_drives_unprotected",
                          "bitlocker_removable_unprotected"):
                ctx.mark_error(field, reason)
            return

        volumes = [v for v in as_list(cap.data) if isinstance(v, dict)]

        os_volumes = [v for v in volumes if v.get("VolumeType") == "OperatingSystem"]
        if os_volumes:
            ctx.set("bitlocker_os_drive_protected", all(v.get("ProtectionStatus") == "On" for v in os_volumes))
        else:
            ctx.mark_error("bitlocker_os_drive_protected", "No operating system volume reported by Get-BitLockerVolume")

        ctx.set("bitlocker_fixed_drives_unprotected", [
            v["MountPoint"] for v in volumes
            if v.get("VolumeType") == "Fixed" and v.get("ProtectionStatus") != "On"
        ])
        ctx.set("bitlocker_removable_unprotected", [
            v["MountPoint"] for v in volumes
            if v.get("VolumeType") == "Removable" and v.get("ProtectionStatus") != "On"
        ])

    def _collect_smb_shares(self, ctx: CollectorContext) -> None:
        cap = run_ps_capture("Get-SmbShare -ErrorAction Stop | Select-Object Name,Path")
        if not cap.ok:
            reason = cap.error or "unknown error querying Get-SmbShare"
            ctx.mark_error("non_default_smb_shares", reason)
            ctx.mark_error("non_default_smb_shares_count", reason)
            return

        shares = [s for s in as_list(cap.data) if isinstance(s, dict)]
        non_default_shares = [
            s for s in shares
            if s.get("Name") not in _DEFAULT_ADMIN_SHARES
            and not (len(s.get("Name", "")) == 2 and s["Name"].endswith("$") and s["Name"][0].isalpha())
        ]
        ctx.set("non_default_smb_shares", non_default_shares)
        ctx.set("non_default_smb_shares_count", len(non_default_shares))

    def _collect_system_dir_acl(self, ctx: CollectorContext) -> None:
        cap = run_ps_capture(
            "(Get-Acl 'C:\\Windows' -ErrorAction Stop).Access | "
            "ForEach-Object { [PSCustomObject]@{ Identity = $_.IdentityReference.Value; "
            "Rights = $_.FileSystemRights.ToString(); Type = $_.AccessControlType.ToString() } }"
        )
        if not cap.ok:
            ctx.mark_error("system_dir_unexpected_write_access", cap.error or "unknown error querying Get-Acl")
            return

        entries = [e for e in as_list(cap.data) if isinstance(e, dict)]
        unexpected = [
            e for e in entries
            if e.get("Type") == "Allow"
            and e.get("Identity") not in _TRUSTED_ACL_IDENTITIES
            and any(marker in (e.get("Rights") or "") for marker in _WRITE_RIGHTS_MARKERS)
        ]
        ctx.set("system_dir_unexpected_write_access", len(unexpected) > 0)
        ctx.set("system_dir_unexpected_write_acl_entries", unexpected)
