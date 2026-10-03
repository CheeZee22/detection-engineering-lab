# Scheduled Task Created via Command Line

- **Rule file:** `rules/scheduled_task_creation.yml`
- **MITRE ATT&CK:** [T1053.005 Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
- **Log source:** Windows process creation (Sysmon Event ID 1 / Security Event ID 4688)
- **Level:** low (broad coverage; intended for hunting and context, not urgent alerting)

## What it detects

`schtasks.exe` creating a scheduled task. Attackers use scheduled tasks to keep access after a reboot or logon (persistence) and to run code on a schedule or as SYSTEM.

## Logic

Alert when the process is `schtasks.exe`, matched by **either** its file path (`Image` ends with `\schtasks.exe`) **or** its built-in name (`OriginalFileName` is `schtasks.exe`, which survives renaming), **and** the command line contains `/create` or `-create`. Sigma matching is case-insensitive, so `/CREATE` and `/Create` are covered.

## Testing

- **Tool:** [Chainsaw](https://github.com/WithSecureOpenSource/chainsaw) v2.16.5 with the `sigma-event-logs-all.yml` mapping
- **Data:** [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)

| Test run | Files | Hits | True positives | False positives | Notes |
|----------|-------|------|----------------|-----------------|-------|
| Targeted: Persistence folder | 22 | 0 | 0 | 0 | Only one `schtasks.exe` event in this folder: a built-in Windows component (`wsqmcons.exe`, as SYSTEM) **deleting** its own telemetry task. Correctly not flagged (true negative). |
| Full sample set | 278 | 7 | 7 | 0 | Spread across other tactic folders; all classified below |

**True negative check:** I searched the Persistence folder for any `schtasks` activity (`chainsaw search -i "schtasks"`) to see why the targeted run had no hits. The only event was Windows' Customer Experience Improvement Program (`wsqmcons.exe`) running `schtasks /delete` on its own task. The rule ignored it because it matches task creation only, confirming it doesn't fire on routine task maintenance.

## Hit classification

| # | Host / time (UTC) | Parent | What the task does | Red flags | Verdict |
|---|-------------------|--------|--------------------|-----------|---------|
| 1 | IEWIN7, 2019-05-12 | `python.exe` | Task "elevator" created from an XML file in `AppData\Local\Temp` | Unusual parent, XML from Temp, name suggests privilege elevation | True positive |
| 2 | IEWIN7, 2019-05-21 | `mshta.exe` | Task "MSOFFICE_" runs `mshta.exe` against a remote URL every 60 minutes | Imitates Office, fetches a remote payload hourly | True positive |
| 3 | IEWIN7, 2019-05-27 | `cmd.exe` (SYSTEM) | Random-named task runs `svhost64.exe` from a Volume Shadow Copy path every minute | Random name, payload hidden in a shadow copy, `svhost64` imitates `svchost` | True positive |
| 4 | MSEDGEWIN10, 2019-07-19 | `cmd.exe` | One-time task "spawn" runs `cmd.exe` | Matches an Atomic Red Team test pattern | True positive (simulation) |
| 5 | MSEDGEWIN10, 2019-07-19 | `cmd.exe` | Task run as `DOMAIN\user` with the password in the command line (`/RP`) | Plaintext credentials exposed in process logs | True positive (simulation) |
| 6 | MSEDGEWIN10, 2019-07-29 | `cmd.exe` | Task "mysc" runs `calc.exe` at every logon as System | Logon persistence with high privilege; calc is a common test stand-in for a payload | True positive (simulation) |
| 7 | MSEDGEWIN10, 2020-10-23 | `cmd.exe` (SysWOW64) | Task "DataUsageHandlers" created from a `.tmp` file used as XML | Legitimate-sounding name, task definition disguised as a temp file | True positive |

Related techniques seen: T1218.005 (Mshta, hit 2), T1036.005 (Masquerading: match legitimate name, hits 2, 3, 7), T1552 (Unsecured Credentials, hit 5).

## Benchmark against a SigmaHQ community rule

I ran SigmaHQ's **Suspicious Scheduled Task Creation via Masqueraded XML File** on the same 278 files. It found **1** event, my hit 7, and nothing my rule missed.

That rule fires only when `schtasks /xml` loads a task definition from a file with a non-XML extension. It skipped hit 1 because `elevator.xml` has a normal extension.

**Takeaway:** my rule trades precision for coverage (7 hits, including ones the narrow rule misses), while the community rule trades coverage for confidence (1 highly suspicious hit). In practice, both would run together: the broad rule for hunting and context, the narrow one for alerting.

## False positives and tuning

No false positives appeared, but **this dataset contains only attack activity**, so it can't measure false positives. In a real environment, installers, auto-updaters (browsers, Office, sync clients), and IT management tools create scheduled tasks constantly, which is why this rule is set to `level: low`.

Next tuning step: a higher-severity companion rule, or risk scoring, when a task shows the red flags found above:

- `/tr` runs `mshta`, `powershell`, or `cmd`, or points to `Temp`, `AppData`, `Users\Public`, or a shadow copy path
- Parent process is `mshta`, `wscript`, `cscript`, `python`, or an Office application
- Task runs as SYSTEM or triggers at logon or startup
- `/RP` present (password in the command line)

## Known gaps

- **Tasks created without `schtasks.exe`:** PowerShell `Register-ScheduledTask`, the older `at.exe`, or direct Windows API/COM calls are invisible to this rule.
- **Task-creation logs:** Security Event ID 4698 ("A scheduled task was created") records tasks regardless of the method, but this rule only reads process creation events.
- **Renamed binary:** covered by the `OriginalFileName` branch, but all seven hits also matched on `Image`, so this branch wasn't exercised by the dataset.

## Follow-up detection ideas

- A high-severity companion rule using the red flags above
- A rule on Security Event ID 4698 to catch tasks created by any method

## References

- [MITRE ATT&CK T1053.005](https://attack.mitre.org/techniques/T1053/005/)
- [SigmaHQ rules](https://github.com/SigmaHQ/sigma)
- [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
- [Chainsaw](https://github.com/WithSecureOpenSource/chainsaw)
