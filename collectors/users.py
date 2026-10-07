"""
Users & Account Management collector.

Source: the local Security Accounts Manager (SAM), via the
Microsoft.PowerShell.LocalAccounts module (Get-LocalUser /
Get-LocalGroupMember). Chosen over `net user`/`net localgroup` because it
returns structured objects instead of locale-dependent text tables, and
over Win32_UserAccount because it is faster and scoped to local accounts
by default. Confirmed to run without elevation on a live Windows 11 host.
"""

from __future__ import annotations

from collectors.base import BaseCollector, CollectorContext
from utils.helpers import as_list, days_since, parse_datetime
from utils.powershell import run_ps_capture

INACTIVE_DAYS_THRESHOLD = 90


class UsersCollector(BaseCollector):
    collector_id = "users"

    def _collect(self, ctx: CollectorContext) -> None:
        self._collect_local_users(ctx)
        self._collect_admin_group(ctx)

    def _collect_local_users(self, ctx: CollectorContext) -> None:
        cap = run_ps_capture(
            "Get-LocalUser -ErrorAction Stop | Select-Object Name,Enabled,PasswordRequired,LastLogon,"
            "@{Name='SID';Expression={$_.SID.Value}}"
        )
        if not cap.ok:
            reason = cap.error or "unknown error querying Get-LocalUser"
            for field in ("local_users", "guest_account_enabled", "accounts_without_password",
                          "inactive_accounts_90d", "builtin_admin_enabled"):
                ctx.mark_error(field, reason)
            return

        raw_users = [u for u in as_list(cap.data) if isinstance(u, dict)]

        local_users = []
        accounts_without_password = []
        inactive_accounts = []
        guest_enabled = None
        builtin_admin_enabled = None

        for u in raw_users:
            name = u.get("Name")
            enabled = bool(u.get("Enabled"))
            password_required = bool(u.get("PasswordRequired"))
            last_logon_dt = parse_datetime(u.get("LastLogon"))
            sid = u.get("SID", "") or ""

            local_users.append({
                "name": name,
                "enabled": enabled,
                "password_required": password_required,
                "last_logon": last_logon_dt.isoformat() if last_logon_dt else None,
            })

            if not password_required:
                accounts_without_password.append(name)

            if last_logon_dt is not None:
                age_days = days_since(last_logon_dt)
                if age_days is not None and age_days > INACTIVE_DAYS_THRESHOLD:
                    inactive_accounts.append(name)

            if name and name.lower() == "guest":
                guest_enabled = enabled
            if sid.endswith("-500"):
                builtin_admin_enabled = enabled

        ctx.set("local_users", local_users)
        ctx.set("accounts_without_password", accounts_without_password)
        ctx.set("inactive_accounts_90d", inactive_accounts)

        if guest_enabled is None:
            ctx.mark_error("guest_account_enabled", "Guest account not found in local account list")
        else:
            ctx.set("guest_account_enabled", guest_enabled)

        if builtin_admin_enabled is None:
            ctx.mark_error("builtin_admin_enabled", "Built-in Administrator account (SID -500) not found")
        else:
            ctx.set("builtin_admin_enabled", builtin_admin_enabled)

    def _collect_admin_group(self, ctx: CollectorContext) -> None:
        cap = run_ps_capture(
            "Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | "
            "Select-Object Name,ObjectClass"
        )
        if not cap.ok:
            ctx.mark_error(
                "administrators_group_member_count",
                cap.error or "unknown error querying Get-LocalGroupMember",
            )
            return

        members = [m for m in as_list(cap.data) if isinstance(m, dict)]
        ctx.set("administrators_group_member_count", len(members))
        ctx.set("administrators_group_members", [m.get("Name") for m in members])
