# Architecture

## Pipeline

```
Windows 11 System
        |
        v
Collectors (collectors/*.py)
   BaseCollector.collect() -> CollectionResult
        |
        v
Rule Engine (engine/rule_engine.py)
   load_rules() -> list[Rule]         (config/audit_rules.json)
   run_collectors() -> dict[collector_id, CollectionResult]
        |
        v
Evaluator (engine/evaluator.py)
   evaluate_rule(Rule, results) -> CheckResult   (PASS/FAIL/WARNING/NOT_APPLICABLE/UNABLE_TO_COLLECT)
        |
        v
Scoring (engine/scoring.py)
   compute_scoring(list[CheckResult], severity_config) -> dict
        |
        v
AuditReport (engine/result_model.py)
        |
        v
Reporting (reporting/*.py) -- console / json / csv / html, each independent
```

`main.py` is the only module that wires these together. Every other
module has a narrow, single-purpose contract and does not import the
others' internals.

## Why this shape

The brief's core constraint — no predefined framework, must be
extensible, must not silently guess at unverified state — pushes toward
three hard boundaries:

1. **Collectors know nothing about pass/fail.** They only produce facts.
   This means the definition of "compliant" lives entirely in
   `config/audit_rules.json`, not scattered across seventeen Python files.
2. **The evaluator is the only place a status is decided**, and it
   decides from exactly four inputs: the rule's condition, the collected
   value, whether the collector marked that field not-applicable, and
   whether it marked it errored. There is no fifth path that lets a
   missing value quietly become PASS.
3. **Reporting only reads `AuditReport`.** None of the four report
   generators know what a "collector" or a "rule" is. This is what makes
   adding a fifth format (or changing the HTML layout) a change isolated
   to one file.

## Data model (`engine/result_model.py`)

- `CollectionResult` — one per collector run. Holds `data` (field_path ->
  value), `not_applicable` (field_path -> reason) and `errors`
  (field_path -> reason) as three disjoint maps, plus a collector-level
  `status` (`OK`/`ERROR`/`UNAVAILABLE`). `field_state(path)` resolves
  which of `"ok"`, `"not_applicable"`, `"error"`, or `"ok_missing"`
  applies — this one method is what lets the evaluator never have to
  special-case `None` vs. "didn't collect this."
- `Rule` — one per line in `audit_rules.json`, plus an optional
  `Dependency` (`depends_on`) that names another field in the *same*
  collector and a condition on it.
- `CheckResult` — the per-rule outcome: status, severity, the
  human-readable expected/actual pair, and (when relevant) `detail`
  explaining *why* something is `NOT_APPLICABLE` or `UNABLE_TO_COLLECT`.
- `AuditReport` — timestamp, host, OS info, admin flag, the full list of
  `CheckResult`, any whole-collector errors, and the scoring dict.

## Collector contract (`collectors/base.py`)

```python
class MyCollector(BaseCollector):
    collector_id = "my_collector"

    def _collect(self, ctx: CollectorContext) -> None:
        ctx.set("some_field", True)
        ctx.mark_not_applicable("other_field", "doesn't apply here because...")
        ctx.mark_error("third_field", "couldn't read this because...")
```

`BaseCollector.collect()` wraps `_collect()` in a try/except: an
unhandled exception becomes `CollectionStatus.ERROR` with the exception
message recorded, and the audit continues with the next collector. This
is the single enforcement point for "a collector must never crash the
audit" — individual collectors do not need their own top-level
try/except, which keeps them readable.

### `NOT_APPLICABLE` vs. `UNABLE_TO_COLLECT` — the rule actually used

This distinction was easy to get wrong while implementing collectors
against the real system, so it's made explicit here:

- **`NOT_APPLICABLE`**: the check genuinely doesn't apply given a
  *confirmed* fact about this system (no TPM chip present, legacy BIOS
  not UEFI, RDP disabled so its NLA setting is moot, Edge not installed).
- **`UNABLE_TO_COLLECT`**: the fact *does* matter, but this method
  couldn't determine it — privilege, a missing/ambiguous data source, or
  an unreliable signal.
- **A confirmed absence that IS the answer is not either of the above.**
  E.g. `PoliciesCollector` reading a missing `ScriptBlockLogging`
  registry value sets the field to `False` — the key's absence *is* the
  verified fact that logging isn't configured, so it's a normal
  collected value, not a collection failure. Contrast this with
  `UpdatesCollector`'s legacy Automatic-Updates registry key, whose
  absence says nothing reliable about modern Windows 11's actual update
  behavior — that one is `UNABLE_TO_COLLECT`, not `False`, because
  reporting it either way would be a guess.

## PowerShell invocation (`utils/powershell.py`)

Two functions, and collectors should not shell out any other way:

- `run_powershell(command)` — launches `powershell.exe -NoProfile
  -NonInteractive -ExecutionPolicy Bypass -Command <command>`, parses
  stdout as JSON, and turns timeout/missing-executable/non-zero-exit/
  malformed-JSON into an explicit `PowerShellResult`.
- `run_ps_capture(expression)` — wraps `expression` in a PowerShell-side
  `try { $__data = <expression> } catch { $__err = $_.Exception.Message }`
  and emits `{ok, data, error}` as JSON. **This exists because exit code
  and stderr are not reliable failure signals for a PowerShell cmdlet
  failing internally** — confirmed live on Windows 11 build 26200:

  ```
  $ powershell.exe -NoProfile -NonInteractive -Command "Get-BitLockerVolume | ConvertTo-Json"
  # (as non-admin) exits 0, stdout: "Access denied "
  ```

  Exit code 0. No stderr. The "successful" JSON output is a bare string
  containing an error message — `json.loads()` would happily parse it as
  a valid (wrong) result if nothing else caught it. `run_ps_capture`'s
  explicit `{ok, data, error}` envelope is what makes this distinguishable
  from a real result.

### Other PowerShell pitfalls found only by testing against a live machine

- **`Get-Tpm`** does *not* raise a catchable exception when run
  non-elevated and only specific properties are selected — it silently
  returns those properties as `null`. `SystemCollector` cannot
  distinguish "no TPM" from "insufficient privilege" in that case and
  reports `UNABLE_TO_COLLECT` rather than guessing.
- **`.NET` enums serialize as bare integers** unless explicitly cast:
  `Get-Service.Status`/`.StartType`, `Get-ExecutionPolicy`'s `Scope`/
  `ExecutionPolicy`, and `Get-NetFirewallProfile.Enabled` all do this.
  Every collector that touches one of these casts it to string/bool
  *inside* the PowerShell expression (`.ToString()` / `[bool]`) rather
  than guessing at the undocumented integer mapping in Python.
  (`Win32_Service.State`, by contrast, is natively a string — confirmed
  live — so no cast is needed there.)
- **Dates are not ISO-8601.** Windows PowerShell 5.1's `ConvertTo-Json`
  renders `[DateTime]` using the legacy AJAX `"/Date(ms)/"` convention
  (confirmed on `Win32_OperatingSystem.LastBootUpTime`,
  `Get-LocalUser.LastLogon`). Some CIM datetime properties instead arrive
  as `{"value": "/Date(...)/", "DateTime": "<readable string>"}`
  (confirmed on `Win32_QuickFixEngineering.InstalledOn`). `utils/helpers.py::parse_datetime()`
  handles both forms plus ISO-8601 as a fallback.
- **`Get-WinEvent` throws when a filter matches zero events** ("No events
  were found...") — a normal, valid outcome (zero failed logons), not a
  failure. `EventLogsCollector` checks for that specific message before
  treating a `run_ps_capture` failure as a real error.
- **Get-ItemProperty on a full registry path returns PowerShell provider
  metadata** (`PSPath`, `PSProvider`, ...) alongside the real values
  unless you pass `-Name`, and `PSProvider` recursively serializes .NET
  reflection metadata that blows up into tens of KB of noise. This is
  the main reason registry reads in this project go through
  `utils/registry.py` (`winreg` directly) instead of PowerShell.
- **A single-item PowerShell array collapses to a bare object** through
  `ConvertTo-Json`, not a one-element JSON array. `utils/helpers.py::as_list()`
  normalizes this back.

## Registry access (`utils/registry.py`)

Thin `winreg` wrapper returning `RegistryReadResult(exists, value, error)`.
The three-way distinction matters: a missing key/value is `exists=False,
error=None` (a legitimate, common, often-meaningful state), while a
permission error or unexpected `OSError` is `exists=False, error="..."`.
Collectors must not conflate the two.

## Evaluator (`engine/evaluator.py`)

`evaluate_rule(rule, results)`:

1. If the rule's collector didn't run, or the whole collector crashed
   (`CollectionStatus.ERROR`) -> `UNABLE_TO_COLLECT`.
2. If `depends_on` is set, resolve its field's state first:
   `not_applicable` cascades to `NOT_APPLICABLE`; `error`/missing
   cascades to `UNABLE_TO_COLLECT`; otherwise evaluate the dependency
   condition and short-circuit to `NOT_APPLICABLE` if it isn't met.
3. Resolve the rule's own field's state the same way.
4. Only once a real, present value is confirmed does it get handed to an
   operator function (`is_true`, `in_range`, `warn_if_false`, ...),
   which returns `PASS`/`FAIL`/`WARNING` — never `NOT_APPLICABLE` or
   `UNABLE_TO_COLLECT`, since by this point the data is known-good.

Operator dispatch is a flat `dict[str, Callable]`
(`engine/evaluator.py::_OPERATORS`) — adding an operator means adding one
function and one dict entry; `tests/test_rule_engine.py` asserts every
operator referenced in the real `audit_rules.json` is actually
implemented, so a typo'd operator name fails CI rather than silently
becoming an unhandled-exception at evaluation time (which would still be
caught and reported as `UNABLE_TO_COLLECT`, but a test catches it earlier).

## Scoring (`engine/scoring.py`)

See README.md "Scoring methodology" for the formulas. Implementation
note: `INFO`-severity results and `NOT_APPLICABLE`/`UNABLE_TO_COLLECT`
results are excluded from the weight sums used for `compliance_percent`
and `risk_score`, but are still counted in `coverage_percent`'s
denominator — that's what makes coverage meaningfully drop on a
non-elevated run instead of the compliance score just quietly rising.

## Reporting (`reporting/*.py`)

Four sibling modules, each exposing `generate(report: AuditReport,
output_path)` (console's `generate(report) -> str` is the one exception,
since it has nothing to write to disk). None of them import
`engine.evaluator`, `engine.rule_engine`, or any collector — verified by
inspection, and structurally true since `AuditReport`/`CheckResult` are
plain dataclasses with no back-reference to the objects that produced
them.

## Known performance characteristic

Each `run_ps_capture()` call launches a new `powershell.exe` process
(~1-2s startup cost on this development machine). With ~17 collectors
each making several such calls, a full audit run takes roughly 90-100
seconds end-to-end (confirmed live). This is acceptable for an offline,
on-demand audit tool, but a future improvement would be batching several
related PowerShell queries into one process invocation per collector
rather than one per fact.
