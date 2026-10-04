# Detection Engineering Lab

Three Sigma detection rules written, tested, tuned, and benchmarked against public Windows attack logs, with a write-up for each rule documenting results, false-positive analysis, and known gaps.

## Results

| Rule | MITRE ATT&CK | Hits (full set) | True positives | False positives | Write-up |
|------|--------------|-----------------|----------------|-----------------|----------|
| Suspicious LSASS Memory Access | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | 26 | 26 | 0 | [lsass_access.md](docs/lsass_access.md) |
| Scheduled Task Created via Command Line | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | 7 | 7 | 0 | [scheduled_task_creation.md](docs/scheduled_task_creation.md) |
| Encoded PowerShell Command Line | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | 1 | 1 | 0 | [encoded_powershell.md](docs/encoded_powershell.md) |

Every hit was classified with evidence (parent process, command line, access rights, CallTrace) before being counted as a true positive.

## How I tested

- **Tool:** [Chainsaw](https://github.com/WithSecureOpenSource/chainsaw) v2.16.5, which runs Sigma rules directly against Windows event logs, with the `sigma-event-logs-all.yml` mapping
- **Data:** [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES), 278 public Windows event log files of attack activity (not included in this repo)
- **Environment:** Kali Linux VM

For each rule, I:

1. Ran a **targeted test** against the sample folder for that technique
2. Ran a **full test** against all 278 files
3. **Classified every hit** as a true or false positive, with evidence
4. **Tuned** the rule and measured before/after results
5. **Benchmarked** it against a related [SigmaHQ](https://github.com/SigmaHQ/sigma) community rule

Example hunt command:

```bash
./chainsaw hunt "EVTX-ATTACK-SAMPLES" \
  -s rules/ \
  --mapping mappings/sigma-event-logs-all.yml \
  --csv --output results/all
```

## Key findings

- **A community rule failed silently.** SigmaHQ's LSASS Memory Dump rule returned 0 hits. Isolating one condition at a time showed its SYSTEM-user filter depends on `SourceUser`, which none of the matching events contained (older Sysmon versions don't record it). With the filter removed, it matched 16 events.
- **"Safe-looking" Windows processes were attacks.** `services.exe` and `taskmgr.exe` both accessed LSASS as part of credential dumping. Filtering them by name would have dropped hits from 26 to 23, hiding 3 real attacks.
- **Decoded a web shell's staged loader.** The encoded-PowerShell hit came from the IIS web server process. Decoding the payload showed it XOR-decrypts hidden files, runs them in memory, and deletes evidence.
- **Broad and narrow rules catch different attacks.** In every benchmark, my rules and the community rules each caught attacks the other missed.

## Limitations

- **This dataset contains almost only attack activity**, so it can't measure false-positive rates. Real-world tuning would need a baseline of normal activity.
- **Some tuning changes are untested against real attacks**, because the samples don't contain those variants (noted in each write-up).

## What I learned

Testing a rule means testing it against your own data. A rule can be correct in theory and still fail silently when logs don't contain the fields it assumes. I also learned to filter by evidence rather than by process name, and to verify each hypothesis before writing it up. I used AI as a learning aid and for script drafting, and I reviewed, tested, and can explain everything here.

## Repo layout

| Folder | Contents |
|--------|----------|
| `rules/` | The three Sigma rules |
| `docs/` | One write-up per rule: logic, test results, hit classification, benchmark, tuning, known gaps |
| `results/` | Chainsaw CSV output from the test runs |
| `scripts/` | `summarize_hits.py`, a Python script that summarizes hunt results ([usage](scripts/README.md)) |
