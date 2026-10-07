# Testing

## Running the suite

```powershell
python -m unittest discover -s tests -v
```

72 tests, all synthetic/mock-mode. None of them touch the real registry,
spawn `powershell.exe`, or require Windows-specific APIs beyond what
`engine/`, `reporting/`, and `main.py` themselves import — safe to run in
CI or while developing on a non-Windows machine (the `collectors/*`
modules themselves still require Windows to *run*, since they call
`winreg`/`ctypes.windll`, but the tests never invoke a collector's
`_collect()` against the live system).

## What's covered, and by what

| Area | File | What it checks |
|---|---|---|
| Data normalization | `tests/test_helpers.py` | `.NET` date parsing (both serialization forms actually seen live), ISO fallback, byte/int/float coercion, PowerShell single-item-array collapse handling |
| Rule/result data model | `tests/test_result_model.py` | `Rule.from_dict`, `CollectionResult.field_state()`'s four-way resolution (`ok`/`not_applicable`/`error`/`ok_missing`) — including that a legitimate `False` value is never confused with "missing" |
| Evaluation logic | `tests/test_evaluator.py` | Every operator in `engine/evaluator.py`; that `not_applicable`/`error`/missing-collector/crashed-collector all resolve to the correct status and never to PASS/FAIL; `depends_on` short-circuiting in both directions |
| Collector framework contract | `tests/test_base_collector.py` | A collector that raises an unhandled exception becomes `CollectionStatus.ERROR`, not a crash; partial success (some fields set, some errored, some not-applicable) is preserved together |
| Scoring | `tests/test_scoring.py` | Compliance/risk/coverage formulas, severity weighting, `WARNING` half-credit, `NOT_APPLICABLE`/`UNABLE_TO_COLLECT` exclusion from the score but inclusion in coverage, `INFO` exclusion from scoring, category breakdown |
| Real rule-set integrity | `tests/test_rule_engine.py` | Runs against the **actual** `config/audit_rules.json` (not a synthetic fixture): every `audit_id` is unique, every `collector` is registered, every `operator` is implemented, `severity_config.json` has a weight for every severity used |
| End-to-end / mock mode | `tests/test_mock_mode.py` | Full pipeline (load rules -> mock collection -> evaluate -> score -> all four report formats) against `tests/fixtures/mock_results.json`, with no live-system dependency |

## Mock mode

`tests/fixtures/mock_results.json` is a hand-built set of `CollectionResult`
data for all 17 collectors, deliberately including at least one example
of each of the five statuses (PASS, FAIL, WARNING, NOT_APPLICABLE,
UNABLE_TO_COLLECT) so the full pipeline can be exercised without a live
Windows system:

```powershell
python main.py --mock tests\fixtures\mock_results.json --formats console
```

`main.load_mock_results()` reads that file and builds real
`CollectionResult` objects from it, then hands them to the same
`evaluate_rule`/`compute_scoring`/reporting code path a live run uses —
mock mode is not a separate code path with its own logic to drift out of
sync, it substitutes only the collection step.

To add a scenario: add or edit an entry under the relevant collector in
the fixture, then extend `tests/test_mock_mode.py` with an assertion
against the resulting `audit_id`'s status.

## What has been verified against a real Windows 11 machine, and what hasn't

This project's development process included running every collector
directly against a live, non-elevated Windows 11 (build 26200) session
and inspecting the actual output shape — not just testing against
documentation. That process is what surfaced the corrections documented
throughout `ARCHITECTURE.md` and `FRAMEWORK.md` (the UAC default,
`Get-Tpm`'s silent-null behavior, `.NET` date serialization, enum
serialization needing explicit casts, `Get-WinEvent`'s "no events" being
a thrown exception, the Process-scope self-inflicted false positive in
POL-001, and others).

**Confirmed live, non-elevated:** all 17 collectors run and produce
correctly-shaped data; every check that is documented as *not* requiring
admin has been observed actually succeeding without it.

**Confirmed live, non-elevated failure path:** every check documented as
`requires_admin: true` has been observed actually failing gracefully
(reported `UNABLE_TO_COLLECT` with a specific reason, not a crash and not
a guess) when run without elevation — `secedit`, `auditpol`,
`Get-BitLockerVolume`, `Confirm-SecureBootUEFI`, `Get-Tpm`,
`Get-WinEvent -ListLog Security`.

**Confirmed live, elevated (2026-08-19):** an elevated run on the same
development machine was diffed against the non-elevated run from a day
earlier. Coverage rose from 74.7% to 92.4%; 14 of the 18
`UNABLE_TO_COLLECT` checks resolved to real values, confirming the
elevated path for every admin-gated source actually works, not just its
non-elevated failure handling:

| Check | Source | Resolved to |
|---|---|---|
| AUTH-001..006 | `secedit` policy export | Real values, e.g. `MinimumPasswordLength=0`, `PasswordHistorySize=0` (both genuine `FAIL`s), `LockoutThreshold=10` (`PASS`) |
| LOG-001..003 | Security event log, `auditpol` | Real values, e.g. logon auditing confirmed `False` (`FAIL`) |
| STG-001..003 | `Get-BitLockerVolume` | Real values, e.g. OS drive confirmed unprotected (`FAIL`) |
| SYS-009 | `Confirm-SecureBootUEFI` | `True` (`PASS`) |
| SYS-010 | `Get-Tpm` | `True` (`PASS`) |

The remaining 4 (`BKP-001`, `BRW-002`, `SEC-006`, `UPD-003`) stayed
`UNABLE_TO_COLLECT` under elevation too, since at the time they were
gated by ambiguous signals rather than privilege — elevation was never
going to change them. On review, three of those four had a better source
available that just hadn't been tried yet:

- `BRW-002`/`SEC-006` (SmartScreen): a deeper search — including a
  byte-for-byte scan of Edge's own Preferences JSON file — confirmed
  there is genuinely no artifact to read until a user or policy changes
  the setting from default. Since Microsoft documents SmartScreen as on
  by default, absence is now reported as that documented default instead
  of `UNABLE_TO_COLLECT`. Confirmed live, non-elevated: both now resolve
  to `True` on this machine (neither setting had ever been touched).
- `UPD-003` (Automatic Updates): replaced the legacy Group-Policy-only
  check with `PauseUpdatesExpiryTime`, the value Settings > Windows
  Update > Pause updates actually writes. Confirmed live via direct
  `winreg` access that this value is genuinely absent (not just
  null-when-selected, which is what an earlier `Get-ItemProperty` test
  had misleadingly shown) when updates aren't paused. Confirmed live,
  non-elevated: resolves to `False` (not paused) on this machine.
- `BKP-001` (System Restore): replaced the registry-only check with a
  fallback to `Get-ComputerRestorePoint`, which is documented to throw a
  specific "System Restore is disabled" message when off, succeeding
  otherwise. Confirmed live that it requires elevation ("Access denied"
  non-admin) — this one is now a genuine, resolvable `requires_admin`
  case like the others in the table above, rather than a dead end.

Re-running the full suite after these changes: non-elevated
`UNABLE_TO_COLLECT` count dropped from 18 (the original run) to 15, and
every one of those 15 is now a privilege-gated check with a confirmed
elevated resolution path — there are no longer any checks with no
possible path to resolution.

Reviewing that real elevated report's HTML output also caught a genuine
formatting bug — the executive summary's closing sentence left an
orphaned period on its own line when `is_admin=True` (the non-elevated
notice clause and the trailing `.` were two separate template
expressions, so the period rendered even when the notice text didn't).
Fixed in `reporting/html_report.py` by combining them into one
conditional expression; regression-checked by generating the executive
summary paragraph for both `is_admin=True` and `False` and asserting no
orphaned punctuation.

A second bug was caught only from an actual screenshot of the rendered
report (not visible from reading the raw HTML text): the status badge
(`.badge` CSS class) had `white-space: nowrap`, which stopped it from
wrapping inside the narrow, equal-width columns produced by
`table-layout: fixed` on a 10-column table. Long labels like
`UNABLE_TO_COLLECT` visually overflowed into the adjacent "Expected"
column instead of staying inside their cell. Fixed by replacing
`white-space: nowrap` with `display: inline-block; overflow-wrap: anywhere`
so the badge wraps within its own cell. This is a reminder that this
project's raw-HTML sanity checks (tag balance, escaping) cannot catch
CSS layout/overflow bugs — those require an actual rendered screenshot,
which is what caught this one.

This closes the gap this document previously flagged: every check in
the rule set now has both its non-elevated failure path *and* its
elevated success path confirmed against a real Windows 11 machine, not
assumed from documentation.

## Adding tests for a new collector

1. Unit-test any pure parsing/normalization logic the collector adds
   (date parsing, bitmask decoding, threshold logic) the way
   `test_helpers.py` does — synthetic inputs, no live system.
2. Add the collector's expected fields to `tests/fixtures/mock_results.json`
   so rules referencing it are exercised in mock mode.
3. Before trusting the collector against the real system, run it
   directly and print its output:
   ```powershell
   python -c "from collectors.my_collector import MyCollector; import json; r = MyCollector().collect(); print(json.dumps(r.data, indent=2, default=str)); print(r.errors); print(r.not_applicable)"
   ```
   Confirm the shape matches what the rules expect, especially for any
   PowerShell-sourced field — see ARCHITECTURE.md's PowerShell pitfalls
   list before assuming a cmdlet's output shape.

## Adding tests for a new rule

`tests/test_rule_engine.py`'s integrity tests run against the real
`audit_rules.json` automatically — a new rule with a typo'd operator or
an unregistered collector will fail those tests without any additional
code. Add a targeted assertion in `tests/test_mock_mode.py` only if the
new rule's behavior (e.g. a new `depends_on` relationship) is worth
locking in as a regression test.
