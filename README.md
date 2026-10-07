# Windows 11 System Auditing Framework and Automated Security Auditor

A modular, read-only auditing tool for Windows 11 that collects system,
security, configuration, network, user, application, and event-log
information; evaluates it against a configurable audit rule framework;
and produces console, JSON, CSV, and HTML compliance reports.

Built as a DRDO internship engineering project. There is no predefined
external audit framework behind this tool — the rule set in
`config/audit_rules.json` was designed from first principles for this
project (see [FRAMEWORK.md](FRAMEWORK.md) for the rationale behind every
category and check).

## Project purpose

Give a Windows 11 machine a single, offline, read-only tool that answers:
*what is this system's actual security configuration, and where does it
deviate from a defensible baseline?* — without requiring a SIEM agent,
an internet connection, or any change to the system it inspects.

## Design principles

- **Read-only, always.** Nothing in this codebase writes to the registry,
  changes a service, touches Defender/firewall/policy settings, or kills
  a process. `secedit`'s local-policy export is the one command that
  writes anything at all, and it only writes a scratch file in the OS
  temp directory, which this tool deletes after parsing it.
- **Offline, always.** No network calls. No telemetry. Nothing is ever
  sent anywhere — reports are written to local files under `reports/`.
- **Almost no third-party dependencies.** `console`/`json`/`csv`/`html`
  are all standard-library Python (`subprocess`, `winreg`, `ctypes`,
  `json`, `csv`, `html`, `dataclasses`). The one exception is the `pdf`
  format, which uses `fpdf2` to render the PDF directly in Python (no
  browser, no subprocess, no OS print dialog). See `requirements.txt`.
- **Never claim a value that wasn't verified.** A check that couldn't be
  collected is reported as `UNABLE_TO_COLLECT`, distinct from `PASS` and
  `FAIL`. It is never defaulted to either.
- **Never crash the audit.** Every collector runs inside a guard that
  turns any unhandled exception into a recorded collector error, and the
  audit continues with the next collector.

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full pipeline design.
In short:

```
Collectors (collectors/*.py)  --normalized facts-->
Rule Engine (engine/rule_engine.py, engine/evaluator.py)  --CheckResults-->
Scoring (engine/scoring.py)  --compliance % / risk score-->
Reporting (reporting/*.py)  --console / JSON / CSV / HTML-->
```

Collectors, the engine, and reporting are independent of each other.
A new check normally means: add a rule to `config/audit_rules.json`,
and add a field to the relevant collector if the underlying fact isn't
already collected. Nothing else needs to change.

## Auditing framework and categories

See [FRAMEWORK.md](FRAMEWORK.md) for the full framework: every category,
every check, its data source, why that source was chosen over
alternatives, and — just as importantly — what was deliberately **not**
implemented and why.

15 categories, 89 initial checks:

| Category | Prefix | Checks |
|---|---|---|
| System & Hardware | `SYS` | 11 |
| Users & Account Management | `USR` | 6 |
| Authentication & Access Control | `AUTH` | 10 |
| Windows Security | `SEC` | 10 |
| Firewall & Network Security | `NET` | 8 |
| Windows Update & Patch Management | `UPD` | 4 |
| Services | `SVC` | 5 |
| Processes & Applications | `APP` | 4 |
| Remote Access | `RDP` | 4 |
| System Configuration & Policies | `POL` | 3 |
| Data & Storage Security | `STG` | 5 |
| Event & Log Auditing | `LOG` | 4 |
| Device & Peripheral Security | `DEV` | 9 |
| Browser & Internet Security | `BRW` | 3 |
| Backup & Recovery | `BKP` | 3 |

## Rule format

Rules live in `config/audit_rules.json` as a flat list under `"rules"`.
Each rule:

```json
{
  "audit_id": "NET-003",
  "category": "Firewall & Network Security",
  "subcategory": "Firewall Profiles",
  "parameter": "Public Firewall Profile Enabled",
  "description": "Windows Firewall should be enabled on the Public profile...",
  "data_source": "Windows Defender Firewall profile configuration",
  "collection_method": "PowerShell Get-NetFirewallProfile -Profile Public",
  "collector": "firewall",
  "field_path": "public_profile_enabled",
  "expected_condition": { "operator": "is_true" },
  "severity": "CRITICAL",
  "remediation": "Enable Windows Firewall on the Public profile.",
  "enabled": true,
  "requires_admin": false,
  "depends_on": { "field_path": "...", "operator": "equals", "value": true }
}
```

- `collector` + `field_path` locate the fact inside that collector's
  normalized output (see `engine/result_model.py::CollectionResult`).
- `expected_condition.operator` is one of the operators implemented in
  `engine/evaluator.py` (`is_true`, `is_false`, `equals`, `not_equals`,
  `in`, `not_in`, `gte`, `lte`, `gt`, `lt`, `in_range`, `list_empty`,
  `list_not_empty`, `warn_if_true`, `warn_if_false`, `warn_if_not_empty`,
  `not_none`). The `warn_if_*` operators produce `WARNING` instead of
  `FAIL` — used for advisory/soft checks.
- `depends_on` (optional) makes a rule short-circuit to `NOT_APPLICABLE`
  when a prerequisite field (in the same collector) doesn't hold — e.g.
  "RDP must require NLA" only applies when RDP is actually enabled.
- `requires_admin` is documentation for the report/reviewer; the actual
  privilege-driven UNABLE_TO_COLLECT behavior comes from the collector.

## Data collection methods

Every collector goes through one of three chokepoints, never ad hoc:

- `utils/powershell.py::run_ps_capture()` — runs a PowerShell expression
  wrapped in a try/catch that reliably distinguishes success from an
  internal cmdlet failure (confirmed necessary live: some cmdlets exit 0
  even when they've failed internally — see ARCHITECTURE.md).
- `utils/registry.py` — direct `winreg` access for anything that's a
  plain registry value, avoiding PowerShell's registry-cmdlet output
  noise and enum-serialization ambiguity entirely.
- Two collectors (`authentication`, `event_logs`) call `secedit`/`auditpol`
  directly via `subprocess`, since those are external tools, not cmdlets.

See [FRAMEWORK.md](FRAMEWORK.md) for the specific source/method used per
check, and why, including several corrections found only by running
against a real Windows 11 machine (e.g. the UAC default is `5`, not the
commonly assumed `2`; `Confirm-SecureBootUEFI` and even
`Get-WinEvent -ListLog Security` require elevation).

## Installation

No installation needed. Requires Python 3.10+ on Windows 11 (or Windows
10 — most checks are not build-specific).

```powershell
git clone <this repo>
cd windows_auditor
python main.py
```

`requirements.txt` installs `fpdf2`, needed for PDF output, which is
part of the default format list (`console,json,html,csv,pdf`) —
`pip install -r requirements.txt` is required for a normal `python
main.py` run. Drop `pdf` from `--formats` (e.g. `--formats
console,json,html,csv`) to skip that dependency if you don't need PDF.

## Building a portable executable

For target machines without Python installed, build a single-file
`.exe` with [PyInstaller](https://pyinstaller.org/) (a build-time-only
tool — the output has zero runtime dependencies, same as running from
source):

```powershell
pip install pyinstaller
pyinstaller --onefile --name windows_auditor --add-data "config;config" --console --clean main.py
```

This produces `dist\windows_auditor.exe` (~10 MB, self-contained).
Copy that one file anywhere — a USB stick, a different machine — and
run it directly; nothing else needs to be installed or extracted
alongside it.

At runtime the exe anchors all of its paths to **its own folder**, not
the temp directory PyInstaller extracts into internally:

- `reports\` and `reports\logs\` are created next to the exe.
- Rules are loaded from a `config\` folder next to the exe *if one is
  present* (so `audit_rules.json`/`severity_config.json` can be edited
  without rebuilding), falling back to the copy embedded in the exe at
  build time otherwise.

Rebuild after any change to `config/*.json` or the Python source to
refresh the embedded fallback copy. `windows_auditor.spec` (generated
by the command above) records the build configuration for repeat builds
— rerun `pyinstaller windows_auditor.spec` instead of the full command
once it exists. `build\` is scratch output from the build process and
safe to delete; only `dist\windows_auditor.exe` is the deliverable.

## Running the auditor

```powershell
python main.py                                  # all formats, live system
python main.py --formats html,json              # only HTML + JSON
python main.py --output-dir C:\audits\2026-08   # custom output location
python main.py --mock tests\fixtures\mock_results.json --formats console
```

Run from an elevated PowerShell/terminal for full coverage (see below).

## Administrator requirements

Confirmed live against a real, non-elevated Windows 11 session: the
following require elevation and are reported as `UNABLE_TO_COLLECT`
(not skipped, not assumed) when the tool is not run as Administrator:

- Local security policy / password & lockout policy (`secedit`) — `AUTH-001..006`
- Local audit policy (`auditpol`) — `LOG-003`
- Security event log, including just listing its metadata — `LOG-001`, `LOG-002`
- BitLocker status — `STG-001..003`
- `Confirm-SecureBootUEFI` — `SYS-009`
- `Get-Tpm` (returns null properties rather than throwing, when not elevated) — `SYS-010`
- `Get-ComputerRestorePoint`, used to resolve System Restore state when no Group Policy override is present — `BKP-001`

Every check in the rule set now falls into one of two buckets: it runs
fully without elevation, or it is one of the ones listed above and will
resolve once elevated. As of 2026-08-19 there are no remaining checks
that can never be verified regardless of privilege — see FRAMEWORK.md
for the two checks (`SEC-006`, `BRW-002`) that instead fall back to a
documented Microsoft default when no override is present, which is a
different kind of limitation (no artifact exists to read at all, not a
privilege boundary).

The tool detects elevation via `utils/permissions.py::is_admin()` (a
read-only `IsUserAnAdmin()` check) at startup, and never attempts to
self-elevate or bypass a privilege boundary. Every other check (the
large majority) runs without elevation.

Both sides of this boundary have been confirmed live: the non-elevated
`UNABLE_TO_COLLECT` behavior above, and — from an elevated run on
2026-08-19 — that every one of these checks resolves to a real
PASS/FAIL/WARNING once run as Administrator (coverage rose from 74.7%
to 92.4% on the same machine; see TESTING.md for the full diff).

## Report generation

Five independent, engine-agnostic report formats (`reporting/*.py`),
all generated from the same `AuditReport`:

- **Console** — human-readable summary, printed to stdout.
- **JSON** (`reports/audit_report_<timestamp>.json`) — full machine-readable dump.
- **CSV** (`reports/audit_report_<timestamp>.csv`) — one row per check, for spreadsheets.
- **HTML** (`reports/audit_report_<timestamp>.html`) — self-contained, no external assets, includes executive summary, system info, category breakdown, failed/warning/passed/critical findings, remediation list, and a section listing every check that couldn't be collected, with why.
- **PDF** (`reports/audit_report_<timestamp>.pdf`) — the same sections as the HTML report, rendered directly with `fpdf2` (the one non-stdlib dependency in this project, listed in `requirements.txt`). Included by default; drop it with `--formats console,json,html,csv` if you don't want the dependency.

## Scoring methodology

See `config/severity_config.json` and `engine/scoring.py`. Summary:

- Severity weights: CRITICAL=10, HIGH=7, MEDIUM=4, LOW=1, INFO=0 (not scored).
- Status credit: PASS=100%, WARNING=50%, FAIL=0% of a check's weight.
- `compliance % = earned weight / total weight` over checks that were
  actually evaluated (excludes `NOT_APPLICABLE` and `UNABLE_TO_COLLECT`
  from both sides of the fraction — they are not silently treated as
  passing).
- `risk score = failed weight / total weight` — a FAIL-only view,
  weighted so CRITICAL failures dominate the number the way they should.
- `coverage % = evaluated checks / enabled checks` — reported alongside
  compliance so a low-privilege run's high compliance score isn't
  mistaken for "the system is fine" when it mostly means "we couldn't
  check very much."
- Category-wise scores use the same formula scoped to one category.

## Limitations

Documented in detail in [FRAMEWORK.md](FRAMEWORK.md#limitations); the
significant ones:

- No pending-Windows-Update detection (would require contacting a WSUS/
  Windows Update endpoint, violating the offline requirement) — installed-
  update recency is used as a local proxy instead.
- Browser/software version checks are informational only — this tool
  cannot compare against the latest published release without internet
  access.
- Security Center's `productState` bitmask is undocumented and is
  deliberately not decoded; registered AV product names are reported
  for the reviewer's own judgment instead of a fabricated pass/fail.
- SmartScreen checks (`SEC-006`, `BRW-002`) fall back to Microsoft's
  documented on-by-default state when no registry override is present,
  since neither Windows nor Edge persists this setting until changed
  from default — a labeled inference from a published default, not a
  live state read; see FRAMEWORK.md.
- The "processes running from an unusual path" heuristic only flags the
  Temp directories, not all of AppData, to avoid flagging ordinary
  applications — a narrower, lower-false-positive check by design.
- Group Policy RSOP (`gpresult`) is not used; the specific registry keys
  each policy actually writes to are read directly instead, since the
  GroupPolicy module is often absent on non-domain-joined machines.

## Adding new audit rules

1. Confirm the fact you need is already collected (`grep` the field name
   across `collectors/`), or add it to the relevant collector's `_collect()`.
2. Add an entry to `config/audit_rules.json` with a unique `audit_id`,
   the right `collector`/`field_path`, an `expected_condition` using one
   of the existing operators, a `severity`, and a `remediation`.
3. Add the same field/scenario to `tests/fixtures/mock_results.json` if
   you want it exercised in mock mode, and consider adding a rule-set
   integrity assertion in `tests/test_rule_engine.py`.
4. No code change is needed in `engine/` or `reporting/` for a rule that
   only adds a new field to an existing collector.

## Adding new collectors

1. Create `collectors/<name>.py`, subclassing `collectors.base.BaseCollector`,
   setting `collector_id`, and implementing `_collect(self, ctx)`.
   Use `ctx.set(field, value)`, `ctx.mark_not_applicable(field, reason)`,
   and `ctx.mark_error(field, reason)` — never let a field go unset with
   no explanation.
2. Register it in `engine/rule_engine.py::COLLECTOR_REGISTRY`.
3. Write rules referencing `"collector": "<name>"` in `audit_rules.json`.
4. Test the collector directly against a live machine before trusting
   its output (see [TESTING.md](TESTING.md)); PowerShell's JSON
   serialization has several non-obvious pitfalls (see ARCHITECTURE.md)
   that are easy to get wrong without checking real output.

## Testing

See [TESTING.md](TESTING.md). `python -m unittest discover -s tests -v`
runs the full suite (72 tests, all synthetic/mock-mode — no live-system
dependency, safe to run in CI or on non-Windows machines).
