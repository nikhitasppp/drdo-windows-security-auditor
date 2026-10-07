# Auditing Framework

This project does not implement a pre-existing published framework
(CIS, STIG, etc.) — there was no framework provided, and the brief asked
for one to be designed. What follows is that framework: every category
included, why it's included, every check, its data source, and why that
source was chosen when more than one existed. Everything below was
checked against the actual behavior of a real, running Windows 11 (build
26200) machine, not written from documentation alone — see the "verified
live" notes and ARCHITECTURE.md for the specific corrections that
testing produced.

## Framework design principles

1. **Every check must have a named, authoritative Windows data source.**
   No check exists because "it sounds like a good security control" —
   each row below states exactly where its value comes from.
2. **Coverage over completeness.** The 16 categories in the original
   brief map to real Windows subsystems; not every bullet point under
   each category became a check. Several were deliberately excluded or
   downgraded to informational-only when no reliable, non-fragile source
   existed — see "Excluded or downgraded checks" per category and the
   Limitations section.
3. **A check that can produce a false positive on an ordinary consumer
   machine is either narrowed, downgraded to `WARNING`/`INFO`, or
   dropped**, rather than shipped as a hard `FAIL`. Several of these
   decisions were made only after running the tool against a real,
   messy, OEM-bloatware-laden Windows 11 machine and seeing what a naive
   version of the check would have wrongly flagged.

## Severity methodology

| Severity | Meaning | Example |
|---|---|---|
| CRITICAL | Direct, high-likelihood path to compromise | No password required on an enabled account; UAC disabled |
| HIGH | Significant weakening of a core defense-in-depth control | Public firewall disabled; RDP enabled without NLA |
| MEDIUM | Increases attack surface but needs another condition to be exploitable | Weak lockout policy; SmartScreen off |
| LOW | Best-practice deviation or hygiene issue | Stale accounts; Print Spooler running unnecessarily |
| INFO | Not scored — inventory/descriptive data for the reviewer | OS version, installed applications, running processes |

## Scoring methodology

See README.md "Scoring methodology" and `engine/scoring.py`. In short:
severity-weighted compliance % (PASS=full credit, WARNING=half credit,
FAIL=none), a risk score that is FAIL-weight-only, and a coverage %
reported alongside both so a low-privilege run's inflated compliance
score can't be mistaken for "the system is fine."

---

## 1. System & Hardware (`SYS`, 11 checks)

**Why this category exists:** every other check is meaningless without
knowing what the system actually is (OS build, architecture, firmware
mode) — and Secure Boot/TPM are foundational platform-security controls
that many higher-level protections (BitLocker, VBS, Windows Hello)
implicitly depend on.

| ID | Check | Source | Notes |
|---|---|---|---|
| SYS-001..007, 011 | OS/build/arch/host/CPU/RAM/volumes/uptime | `Win32_OperatingSystem`, `Win32_ComputerSystem`, `Win32_Processor`, `Get-Volume` (CIM) | Informational; standard, stable sources |
| SYS-008 | Firmware type (UEFI/Legacy) | Registry key presence: `HKLM\SYSTEM\...\SecureBoot\State` | Presence, not value, is the signal |
| SYS-009 | Secure Boot enabled | `Confirm-SecureBootUEFI` | **Verified live: requires elevation** (not assumed in the original design — corrected after testing); confirmed elevated (2026-08-19) returning `True` on the development machine |
| SYS-010 | TPM ready | `Get-Tpm` | **Verified live:** does not throw when non-elevated; returns null properties instead. Cannot distinguish "no TPM" from "no privilege" without elevation — reported `UNABLE_TO_COLLECT`, not guessed. Confirmed elevated (2026-08-19) returning `True` |

**Excluded:** per-device driver inventory, detailed BIOS field dump —
not security-relevant enough to justify the checks.

---

## 2. Users & Account Management (`USR`, 6 checks)

**Why:** the account list is the attack surface for credential-based
compromise; a single blank-password enabled account defeats every other
control in this framework.

| ID | Check | Source |
|---|---|---|
| USR-001 | Local user inventory | `Get-LocalUser` |
| USR-002 | Guest account disabled | `Get-LocalUser -Name Guest` |
| USR-003 | No account has a blank/not-required password | `Get-LocalUser.PasswordRequired` |
| USR-004 | Administrators group size | `Get-LocalGroupMember Administrators` |
| USR-005 | No account inactive >90 days | `Get-LocalUser.LastLogon` |
| USR-006 | Built-in Administrator (SID `-500`) disabled | `Get-LocalUser`, SID match |

`Get-LocalUser`/`Get-LocalGroupMember` were chosen over `net user`/`net
localgroup` (locale-dependent text parsing) and over `Win32_UserAccount`
(WMI, slower, not local-account-scoped by default). **Verified live**: on
the development machine, the actually-logged-in account had
`PasswordRequired = False` — this is a genuine, real finding this check
is designed to catch, not a hypothetical.

**Excluded:** "account privileges" beyond Administrators-group
membership (full effective-rights enumeration is a much larger, separate
project) and detailed group-membership-graph analysis.

---

## 3. Authentication & Access Control (`AUTH`, 10 checks)

**Why:** password/lockout policy and UAC are the two controls that
determine how hard credential compromise and privilege escalation
actually are, independent of what any individual account looks like.
Automatic screen lock closes a third, physical-access gap: even a
correctly configured account is exposed if an unattended, unlocked
session never times out.

| ID | Check | Source |
|---|---|---|
| AUTH-001..006 | Min password length, complexity, max age, history, lockout threshold, lockout duration | `secedit /export /areas SECURITYPOLICY` |
| AUTH-007 | UAC enabled | Registry `...\Policies\System\EnableLUA` |
| AUTH-008 | UAC admin consent prompt behavior | Registry `...\Policies\System\ConsentPromptBehaviorAdmin` |
| AUTH-009 | Automatic screen lock configured | Registry `...\Policies\System\InactivityTimeoutSecs`, falling back to HKCU `Control Panel\Desktop` screen saver keys |
| AUTH-010 | Automatic screen lock timeout ≤ 15 minutes | Same source as AUTH-009 |

AUTH-009/010 check the machine-wide "Interactive logon: Machine
inactivity limit" GPO first (`InactivityTimeoutSecs`, read from the same
policy key as UAC, also elevation-free), since it enforces a
password-protected lock independent of any user's own settings. When
that policy isn't configured, they fall back to the per-user screen saver
(`ScreenSaveActive`, `ScreenSaverIsSecure`, `ScreenSaveTimeOut`) — but
only when the screen saver is both active *and* secure (password
required on resume); an active-but-insecure screen saver blanks the
display without actually restricting access, so it's treated the same as
no lock configured. AUTH-010 uses `depends_on` against AUTH-009's field
so the timeout check resolves to `NOT_APPLICABLE` rather than a
misleading pass/fail when no lock is configured at all.

`secedit` was chosen over `net accounts` because it's the same
structured source the Local Security Policy snap-in reads, covering both
password and lockout policy in one export — but it writes a scratch file
to parse (deleted immediately after), and **verified live: requires
elevation** (exits with code 740/`ERROR_ELEVATION_REQUIRED` otherwise).

**Correction from live testing:** AUTH-008 originally targeted exactly
`ConsentPromptBehaviorAdmin = 2`. Testing against the real machine showed
Windows 11's actual out-of-box default is `5` ("prompt for consent for
non-Windows binaries on the secure desktop"), which is also a reasonably
secure, Microsoft-default value — not a finding. The rule now accepts
`{2, 5}` and only flags `0` (no prompt at all), `1`, `3`, `4` (which skip
the secure desktop or blanket-elevate).

**Excluded:** Kerberos/NTLM policy (not meaningful for a standalone,
non-domain-joined machine, which is the default Windows 11 case this
tool targets first).

---

## 4. Windows Security (`SEC`, 6 checks)

**Why:** Defender (or an equivalent active AV) and SmartScreen are the
platform's primary real-time malware defenses. The Defender check set
was deliberately narrowed to just two signals — whether it's running,
and how current its signatures are — with the same two-signal shape
applied to Net Protector (NPAV), this environment's mandated third-party
antivirus, rather than trying to audit both products' full feature sets
in parallel.

| ID | Check | Source |
|---|---|---|
| SEC-002 | Defender antivirus engine enabled (i.e. running) | `Get-MpComputerStatus` |
| SEC-008 | Defender signature last-updated date (informational) | `Get-MpComputerStatus`, `AntivirusSignatureLastUpdated` |
| SEC-011 | Net Protector running (`ZeroVProtect` service) | `Get-Service -Name ZeroVProtect` |
| SEC-012 | Net Protector last-updated date (informational) | WMI `root\SecurityCenter2\AntivirusProduct`, `timestamp` |
| SEC-006 | SmartScreen enabled | Registry: per-user `Explorer\SmartScreenEnabled`, falling back to policy `System\EnableSmartScreen` |
| SEC-007 | Registered AV products | WMI `root\SecurityCenter2\AntivirusProduct` |

**Net Protector (SEC-011/012):** NPAV does not expose a documented
PowerShell module or registry key equivalent to `Get-MpComputerStatus`.
`ZeroVProtect` is confirmed (via NPAV's own support documentation) as its
main real-time-protection shield service, so SEC-011 reads that service's
running state the same way `services.py` already reads `SDRSVC`/`wuauserv`
elsewhere in this project. SEC-012 has no equivalent dedicated API either;
the least-unreliable available signal is the `timestamp` Windows Security
Center records against whichever registered `AntivirusProduct` entry
matches "Net Protector"/"NPAV" — the same WMI class SEC-007 already reads,
just keyed to one product and one extra field. If Net Protector is not
installed (no `ZeroVProtect` service, and no matching Security Center
entry), both are reported `NOT_APPLICABLE`, never a false `FAIL` or
`UNABLE_TO_COLLECT`.

**Correction from live testing, and a deliberate scope decision:** the
development machine runs Defender in passive mode (real-time protection
and the `WinDefend` service both off) because two third-party AV products
are installed (Security Center registration confirmed this). Rather than
suppress SEC-002 as "not applicable" when a third-party AV is present —
which would hide a genuinely important fact from the reviewer — this
framework keeps it as a real, scored check, and keeps SEC-007 as an
**informational** cross-reference so the report shows *both* "Defender is
passive" and "here's what's registered instead," letting a human
compliance reviewer judge whether that's acceptable. SEC-007 deliberately
does **not** decode Security Center's `productState` field: that bitmask
is legacy and undocumented by Microsoft, and decoding it "well enough"
to fake a pass/fail would violate this project's "never report a value
that wasn't actually verified" principle. Product *names* are verifiable;
a decoded enabled/disabled claim from that field would not be.

**Correction from live testing, SEC-006:** the original version checked
only the two registry overrides and reported `UNABLE_TO_COLLECT` when
neither was present. Confirmed live (including a byte-for-byte search of
Microsoft Edge's own Preferences JSON file) that Windows genuinely does
not persist this setting anywhere until a user or policy explicitly
changes it away from default — there is no missing privilege or hidden
data source to find. Since Microsoft documents SmartScreen as on by
default on Windows 11, absence is now reported as that documented
default rather than as unverifiable. This is explicitly a policy
decision based on a published default, not a live-verified read of
current state, and the rule's `data_source` field says so.

**Excluded:** Defender ASR (Attack Surface Reduction) rule-by-rule audit,
Defender exclusion list audit — both reasonable future additions, not in
this initial rule set.

---

## 5. Firewall & Network Security (`NET`, 8 checks)

**Why:** the firewall profile state is the base network-perimeter
control; listening ports and DNS/proxy config indicate exposure and
possible tampering.

| ID | Check | Source |
|---|---|---|
| NET-001..003 | Domain/Private/Public firewall profile enabled | `Get-NetFirewallProfile` |
| NET-004 | No legacy/high-risk services listening (FTP, Telnet, TFTP, rexec/rlogin/rsh, VNC) | `Get-NetTCPConnection -State Listen` |
| NET-005 | Network category per adapter | `Get-NetConnectionProfile` |
| NET-006 | DNS servers configured | `Get-DnsClientServerAddress` |
| NET-007 | Proxy configured | Registry `HKCU\...\Internet Settings\ProxyEnable` |
| NET-008 | Wireless network interface disabled (advisory) | `Get-NetAdapter`, `PhysicalMediaType` |

RDP (3389) and SMB/RPC (135/139/445) are deliberately excluded from the
"high-risk ports" list: RDP has its own dedicated check (`RDP-001`), and
SMB/RPC are normal on stock Windows — including them would make NET-004
fail on essentially every machine and get ignored.

**Correction from live testing, NET-008:** the first version filtered on
`PhysicalMediaType -eq '802.11'`, which matches nothing — confirmed live
that Windows actually reports `'Native 802.11'` for a genuine Wi-Fi
adapter. Left as written, the wrong filter would have silently made this
check report "no wireless adapter present" on every real Windows machine
(a false `NOT_APPLICABLE`, never a false pass/fail, but still wrong) —
caught only by testing the exact PowerShell expression against a live
adapter before shipping it, not by reasoning about the API from memory.
Like the Bluetooth check below, this is advisory (`warn_if_true`): an
enabled radio is real attack surface, but disabling Wi-Fi outright is
not appropriate for every system.

**Excluded:** full firewall-rule-by-rule audit (thousands of rules on a
typical system; a coarser profile-level check is the practical starting
point), IPv6-specific configuration checks.

---

## 6. Windows Update & Patch Management (`UPD`, 4 checks)

**Why:** unpatched systems are the single most common initial-access
vector; this category exists to catch that even though (see Limitations)
it can't do it the "obvious" way.

| ID | Check | Source |
|---|---|---|
| UPD-001 | Windows Update service running | `Get-Service wuauserv` |
| UPD-002, 004 | Days since / date of last installed update | `Win32_QuickFixEngineering` |
| UPD-003 | Automatic Updates not paused | Registry `...\WindowsUpdate\Auto Update\NoAutoUpdate` (hard override), falling back to `...\WindowsUpdate\UX\Settings\PauseUpdatesExpiryTime` |

**Deliberately not implemented:** checking for *pending* updates. Doing
so requires either the Windows Update Agent COM `UpdateSearcher` or
contacting a WSUS/Windows Update endpoint — both need network access,
which conflicts with this project's offline requirement. Installed-update
recency is used as the closest available offline proxy instead. This is
a real capability gap, stated plainly rather than worked around with a
fragile heuristic.

**Correction from live testing:** UPD-003 originally checked only the
legacy Group-Policy `Auto Update` key, whose absence is normal on a
default consumer Windows 11 install and says nothing about modern update
management — that version always reported `UNABLE_TO_COLLECT` on an
untouched install. Replaced with a check of `PauseUpdatesExpiryTime`,
the value written by Settings > Windows Update > Pause updates.
Confirmed live via direct `winreg` access (not PowerShell's
`Get-ItemProperty`, which silently substitutes a null placeholder for a
requested-but-absent property and would have been misleading here) that
the parent key genuinely exists with real values while this specific
value is genuinely absent when updates are not paused — a definite,
verifiable signal, and one that does not require elevation.

---

## 7. Services (`SVC`, 5 checks)

**Why:** the state of a handful of specific services is a more reliable,
faster signal than trying to audit all ~150 services on a typical
Windows 11 install.

| ID | Check | Source |
|---|---|---|
| SVC-001, 002 | Firewall (`mpssvc`), Defender (`WinDefend`) service running | `Win32_Service` (CIM) |
| SVC-003 | Remote Registry disabled | `Get-Service RemoteRegistry` |
| SVC-004 | Print Spooler (advisory only — PrintNightmare-class risk) | `Get-Service Spooler` |
| SVC-005 | Full auto-start service inventory | `Win32_Service` where `StartMode='Auto'` |

`Win32_Service.State` was confirmed live to serialize as a plain string
("Running"/"Stopped"), unlike `Get-Service.Status` which is a bare
integer enum unless explicitly cast — the two services with dedicated
security checks use the CIM source for exactly that reason.

**Excluded:** a general "is this an unrecognized/suspicious service"
heuristic — reliably distinguishing OEM bloatware from something
malicious from service metadata alone is not something this rule set
attempts; SVC-005's full inventory is reported so a human reviewer can.

---

## 8. Processes & Applications (`APP`, 4 checks)

**Why:** installed software and the current process list are the
baseline inventory a reviewer needs, and processes launching from
user-writable locations are a common, checkable malware indicator.

| ID | Check | Source |
|---|---|---|
| APP-001 | Installed applications | Registry `Uninstall` keys (HKLM native + WOW6432Node) |
| APP-002 | Excessive startup entries (>20, advisory) | Registry `Run`/`RunOnce` keys |
| APP-003 | Running processes | `Get-Process` |
| APP-004 | Processes running from Temp | `Get-Process` + path check against `%TEMP%`/`%TMP%` |

**Deliberate exclusion, justified by Win32_Product's documented side
effect:** installed-application inventory uses the registry Uninstall
keys, not the `Win32_Product` WMI class. Microsoft documents that
querying `Win32_Product` can trigger an MSI consistency-check/repair as a
side effect — that would make this "read-only" tool not actually
read-only, so it's avoided entirely.

**Deliberate narrowing to reduce false positives:** APP-004 only flags
processes running from the Temp directories, not all of `%AppData%` —
many entirely legitimate applications (chat clients, editors, browser
helper processes) run from AppData\Local/Roaming, and a broader check
would flag most of them. This was confirmed as a real risk during
testing: this tool's own development machine had a legitimate VS Code
updater executable running from Temp at the time of a test run, which
the narrower check correctly reported as advisory-worth-a-look rather
than the broader version incorrectly treating dozens of normal AppData
processes as suspicious.

---

## 9. Remote Access (`RDP`, 4 checks)

**Why:** remote-access surfaces (RDP, Remote Assistance, WinRM) are
high-value targets and commonly the first thing disabled in a hardening
pass, or the first thing an attacker looks for if left on.

| ID | Check | Source |
|---|---|---|
| RDP-001 | RDP enabled | Registry `...\Terminal Server\fDenyTSConnections` |
| RDP-002 | RDP requires NLA (only if RDP enabled — `depends_on`) | Registry `...\WinStations\RDP-Tcp\UserAuthentication` |
| RDP-003 | Remote Assistance enabled | Registry `...\Remote Assistance\fAllowToGetHelp` |
| RDP-004 | WinRM running (advisory) | `Get-Service WinRM` |

RDP-002 is the framework's canonical example of `depends_on`: checking
NLA when RDP is off entirely is meaningless, so it resolves to
`NOT_APPLICABLE` rather than a misleading PASS or FAIL.

---

## 10. System Configuration & Policies (`POL`, 3 checks)

**Why:** PowerShell's own execution policy and script-block logging
determine how visible and how restricted script-based attack techniques
are on this system — directly relevant given this very tool uses
PowerShell as a collection mechanism.

| ID | Check | Source |
|---|---|---|
| POL-001 | No persistent scope has an Unrestricted/Bypass execution policy | `Get-ExecutionPolicy -List` |
| POL-002 | PowerShell Script Block Logging enabled (advisory) | Registry `...\PowerShell\ScriptBlockLogging` |
| POL-003 | Device installation restriction policy configured (advisory) | Registry `...\DeviceInstall\Restrictions` |

**Correction from live testing — this one is subtle and important:**
this auditor invokes PowerShell with `-ExecutionPolicy Bypass` for every
one of its own commands. The first version of POL-001 checked all scopes
including `Process`, which meant it would **always** see `Bypass` at
Process scope as an artifact of its own invocation — a self-inflicted
false positive on every single run, regardless of the system's real
policy. Confirmed live and fixed: the `Process` scope is now excluded,
and only the four persistent scopes (`MachinePolicy`, `UserPolicy`,
`CurrentUser`, `LocalMachine`) are evaluated. On the development machine,
`LocalMachine` was genuinely set to `Bypass` independent of this tool —
a real, correctly-detected finding, once the self-inflicted noise was
removed.

**Excluded:** full Group Policy RSOP audit (`gpresult`) — the
`GroupPolicy` PowerShell module is frequently absent on non-domain-joined
machines, and parsing `gpresult`'s text/XML output is exactly the kind of
fragile text-scraping this project avoids. The specific registry keys
each policy actually writes to are read directly instead (see UAC, RDP,
SmartScreen, device-install-restriction above), which is both more
reliable and more directly authoritative.

---

## 11. Data & Storage Security (`STG`, 5 checks)

**Why:** encryption-at-rest and share/permission hygiene determine what
happens to data if a device is lost, stolen, or accessed by an
unauthorized local user.

| ID | Check | Source |
|---|---|---|
| STG-001..003 | BitLocker on OS drive / fixed drives / removable drives | `Get-BitLockerVolume` |
| STG-004 | No non-default SMB shares | `Get-SmbShare` (excluding `ADMIN$`/`IPC$`/`<letter>$`) |
| STG-005 | No unexpected write ACL on `C:\Windows` | `Get-Acl` against a fixed allow-list of trusted principals |

**Verified live:** `Get-BitLockerVolume` requires elevation ("Access
denied" on a non-admin run) — reported `UNABLE_TO_COLLECT`. Confirmed
live on an elevated run (2026-08-19) that the success path also works:
on the development machine, the OS drive was found genuinely
unprotected (`STG-001` correctly `FAIL`), with no unprotected fixed or
removable drives beyond it (`STG-002`/`STG-003` `PASS`) — see
TESTING.md for the full elevated-run diff.

STG-005 is explicitly a best-effort heuristic against a fixed allow-list,
not a full effective-permissions model (which would require correctly
resolving group membership and inheritance) — stated as a limitation,
not oversold as a complete ACL audit.

---

## 12. Event & Log Auditing (`LOG`, 4 checks)

**Why:** without logging and log retention, no other finding in this
report can be investigated after the fact — this category is about
whether the system can support incident response at all.

| ID | Check | Source |
|---|---|---|
| LOG-001 | Security log sized adequately (>=32MB, advisory) | `Get-WinEvent -ListLog Security` |
| LOG-002 | Failed logons (Event ID 4625) in the last 24h | `Get-WinEvent -LogName Security -FilterXPath` |
| LOG-003 | Logon auditing enabled | `auditpol /get /subcategory:Logon /r` |
| LOG-004 | System log available | `Get-WinEvent -ListLog System` |

**Correction from live testing:** the original design assumed only
*reading entries from* the Security log needed elevation. Testing showed
that even `Get-WinEvent -ListLog Security` (metadata only) is denied
without elevation — broader than assumed, and LOG-001's `requires_admin`
flag was corrected accordingly. `auditpol` was chosen over parsing the
Local Security Policy audit-policy UI/export because it emits structured
CSV via `/r`, avoiding locale-dependent text parsing; it, too, requires
elevation, confirmed live ("A required privilege is not held by the
client").

---

## 13. Device & Peripheral Security (`DEV`, 9 checks)

**Why:** peripheral device policy (USB storage, camera/microphone access)
is a real security-relevant surface, but whether it *should* be
restricted is almost entirely organization-specific.

Five checks (`usb_storage_policy_state`, `usb_devices_connected`,
`bluetooth_present`, and the base `webcam_access_setting` /
`microphone_access_setting` reads, DEV-001..005) are reported as
**INFO** — collected and shown, but not scored. Scoring "USB storage
should be disabled" or "camera access should be denied" as a universal
default would produce false positives on essentially every ordinary
consumer/developer machine (including the one this tool was developed
and tested on). Sources: registry `USBSTOR\Start`, `Get-PnpDevice
-Class USB`/`-Class Bluetooth`, and the per-user
`CapabilityAccessManager\ConsentStore` registry keys.

**Four checks are scored as advisory (`WARNING`, not a hard `FAIL`)
rather than INFO**, each because the underlying state is real, if
narrow, attack surface even though disabling it outright isn't
appropriate for every system:

- **DEV-006 (Bluetooth radio enabled, `warn_if_true`)**: an idle
  Bluetooth radio is unambiguous attack surface in a way "USB storage
  is enabled" isn't. Evaluated from the same `Get-PnpDevice -Class
  Bluetooth` call as `bluetooth_present` (`Status = 'OK'` means present
  and enabled) and only runs at all when `bluetooth_present` is true,
  via `depends_on` — a system with no Bluetooth hardware gets
  `NOT_APPLICABLE`, never a misleading pass.
- **DEV-007 (USB storage device connected, `warn_if_not_empty`)**: an
  attached USB mass-storage device is a data exfiltration and
  malware-introduction vector. Deliberately scoped to a *filtered*
  subset of `usb_devices_connected` (`FriendlyName` containing "mass
  storage") rather than the raw list — the raw `Get-PnpDevice -Class
  USB` output always includes root hubs, controllers and composite
  devices that are present on essentially every machine regardless of
  what's plugged in, so warning on "list non-empty" against the
  unfiltered list would fire unconditionally and carry no signal.
- **DEV-008 / DEV-009 (webcam / microphone access allowed,
  `warn_if_equals` "Allow")**: camera/microphone access being globally
  permitted is a real audio/video exfiltration surface, particularly
  relevant in a defense/audit context, but is also the ordinary default
  on consumer systems (video calls, dictation) — hence advisory rather
  than a hard fail.

All four are `MEDIUM` severity, matching the weight given to other
advisory-only checks (e.g. `NET-008` Wi-Fi radio enabled) elsewhere in
this rule set.

---

## 14. Browser & Internet Security (`BRW`, 3 checks)

**Why:** the browser is the most common initial-access surface for a
general-purpose workstation.

| ID | Check | Source |
|---|---|---|
| BRW-001 | Installed browsers + version (informational) | Registry `App Paths` + file `VersionInfo` |
| BRW-002 | Edge SmartScreen enabled (only if Edge installed — `depends_on`) | Registry policy `...\Edge\SmartScreenEnabled` |
| BRW-003 | Browser proxy override configured (advisory) | Registry `HKCU\...\Internet Settings\ProxyEnable` |

Browser detection uses the registry `App Paths` mechanism (the same
lookup Windows itself performs to resolve a bare executable name),
chosen over guessing `Program Files` locations — confirmed live to
correctly find both Edge and Chrome on the development machine.

**Explicit limitation, stated rather than worked around:** this tool is
offline by requirement and therefore cannot compare an installed browser
version against the latest published release. BRW-001 reports the
version as information only; it does not claim "up to date" or
"outdated," which it has no reliable, verified way to determine offline.

**Correction from live testing, BRW-002:** the original version reported
`UNABLE_TO_COLLECT` whenever no Edge policy override was present. A
byte-for-byte search of Edge's own Preferences JSON file (which Edge
writes locally, so reading it doesn't touch the network) turned up no
SmartScreen key at all -- Edge, like the OS-level setting, does not
persist this until it's explicitly changed from default. Since Microsoft
documents Edge SmartScreen as on by default, absence is now reported as
that documented default rather than as unverifiable -- again, a policy
decision based on a published default, not a live-verified read, and
stated as such in the rule's `data_source` field.

---

## 15. Backup & Recovery (`BKP`, 3 checks)

**Why:** recovery capability determines the actual impact of a
ransomware or corruption event, independent of every preventive control
above.

| ID | Check | Source |
|---|---|---|
| BKP-001 | System Restore enabled | Registry `...\SystemRestore\DisableSR` (hard override), falling back to `Get-ComputerRestorePoint` |
| BKP-002 | Windows Backup service state (informational) | `Get-Service SDRSVC` |
| BKP-003 | Recovery partition present | `Get-Partition` |

**Correction from live testing:** neither the `SystemRestore` registry
key nor the `SystemRestoreConfig` WMI class expose a direct per-drive
enabled/disabled flag on this Windows 11 build (confirmed by querying
both). The original version of this check relied only on the Group
Policy override (`DisableSR`), which is absent on almost every consumer
machine — that version reported `UNABLE_TO_COLLECT` in the overwhelming
majority of cases. Replaced with `Get-ComputerRestorePoint` as a
fallback: confirmed live that it requires elevation ("Access denied"
without it), and it is documented to throw "System Restore is disabled
on this computer" when protection is off system-wide, succeeding
otherwise (even with zero existing restore points) — a real signal, not
a guess, though it does mean this check now requires elevation to fully
resolve on a system with no explicit policy override (`requires_admin`
updated accordingly).

---

## Limitations

Consolidated from the per-category notes above:

- **No pending-update detection** (network access required; conflicts
  with the offline requirement). Installed-update recency is the proxy.
- **No version-vs-latest-release comparison** for browsers or any other
  software (same reason).
- **Security Center's `productState` bitmask is not decoded** — it is
  undocumented by Microsoft; product names are reported instead of a
  fabricated pass/fail derived from reverse-engineering an unstable format.
- **SmartScreen checks (`SEC-006`, `BRW-002`) treat an unwritten registry
  value as Microsoft's documented on-by-default state**, not as a
  live-verified read — Windows and Edge both genuinely never persist
  this setting until a user or policy changes it away from default
  (confirmed live, including a search of Edge's own preferences file),
  so there is nothing to read in the common case. This is a defensible,
  clearly-labeled inference from a published default, but it is not the
  same guarantee as a direct state read, and is called out as such in
  each rule's `data_source` field.
- **STG-005's ACL check is a heuristic** against a fixed trusted-principal
  allow-list, not a full effective-permissions/inheritance model.
- **Device/peripheral policy checks are informational only** — whether
  USB storage or camera access *should* be restricted is
  organization-specific, not a universal default.
- **No Group Policy RSOP audit** — the GroupPolicy module is often absent
  on non-domain-joined machines; specific registry keys are read instead.
- **Not every bullet point from the original 16-category brief became a
  check.** Anything without a reliable, non-fragile Windows-native source
  was left out rather than implemented with a guess (see "Excluded"
  notes per category above).
