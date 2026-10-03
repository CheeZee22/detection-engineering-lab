# Suspicious LSASS Memory Access

- **Rule file:** `rules/lsass_access.yml`
- **MITRE ATT&CK:** [T1003.001 OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- **Log source:** Sysmon Event ID 10 (process access)
- **Level:** medium (broad, hunting-oriented; see tuning notes)

## What it detects

A process opening `lsass.exe` with access rights used by credential-dumping tools. LSASS holds logged-in users' credentials in memory, so tools like Mimikatz and ProcDump open it to read or dump that memory.

## Logic

Alert when `TargetImage` ends with `\lsass.exe` **and** `GrantedAccess` exactly matches one of ten values. I took the list from the Splunk Threat Research Team's LSASS hunting research (see References) and checked each value against Microsoft's process access rights documentation:

| GrantedAccess | Rights included | Why it matters |
|---------------|-----------------|----------------|
| `0x1000` | Query limited information | Query-only; used by tools such as PPLdump |
| `0x1010` | Query limited + VM read | Classic Mimikatz `sekurlsa` access |
| `0x1038` | Query limited + VM read/write/operation | Memory read and modification |
| `0x40` | Duplicate handle | Copying an existing LSASS handle instead of opening a new one |
| `0x1400` | Query + query limited | Query-only |
| `0x1410` | Query + query limited + VM read | Common dumping tools |
| `0x1438` | `0x1410` + VM write/operation | Read and modify memory |
| `0x143a` | `0x1438` + create thread | Read, modify, and run code |
| `0x1fffff` | All access | Dumping tools that request everything |

`0x01000` is also in the rule because it appears in the source list, but it's the same number as `0x1000` written differently. Sysmon logs `0x1000`, so `0x01000` is unlikely to ever match.

## Testing

- **Tool:** [Chainsaw](https://github.com/WithSecureOpenSource/chainsaw) v2.16.5 with the `sigma-event-logs-all.yml` mapping
- **Data:** [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)

| Test run | Files | Hits | True positives | False positives |
|----------|-------|------|----------------|-----------------|
| Targeted: Credential Access folder | 39 | 22 | 22 | 0 |
| Full sample set | 278 | 26 | 26 | 0 |

## Hit classification (full set)

| Source | Hits | Access | Verdict and evidence |
|--------|------|--------|----------------------|
| ProcDump (`procdump.exe` / `procdump64.exe`) | 4 | 0x1fffff | TP: Sysinternals dumper; `dbghelp` (memory dump functions) in CallTrace |
| Outflank Dumpert (EXE, plus DLL via `rundll32.exe`) | 6 | 0x1fffff | TP: known LSASS dumper; DLL version visible in `rundll32` CallTrace |
| `AndrewSpecial.exe` | 2 | 0x1fffff | TP: public LSASS-dumping proof of concept |
| `PPLdump.exe` (incl. "BYOV" folder copy) | 3 | 0x1000, 0x1fffff | TP: dumps LSASS even when it runs as a protected process |
| `services.exe` | 2 | 0x1410, 0x1fffff | TP: same second as PPLdump, with `dbgcore` (dump functions) in CallTrace; consistent with PPLdump's payload running inside this system process |
| `taskmgr.exe` | 1 | 0x1fffff | TP: Task Manager "Create dump file," 22 seconds after ProcDump on the same host (living off the land) |
| `mimikatz.exe` | 1 | 0x1010 | TP: classic Mimikatz access |
| `powershell.exe` | 4 | 0x1010, 0x143a | TP: one shows `UNKNOWN(...)` frames in CallTrace, the pattern Splunk documented for Invoke-Mimikatz |
| `python.exe` | 1 | 0x1410 | TP: CallTrace through `_ctypes.pyd`, how Python credential tools call Windows directly |
| `D:\m.exe` | 1 | 0x1410 | TP: one-letter name, run from a D: drive, `UNKNOWN(...)` frames in CallTrace |
| `MalSeclogon.exe` | 1 | 0x1410 | TP: abuses the Secondary Logon service; run by a regular user |

## Key findings

**1. "Safe-looking" Windows processes were real attacks.** `services.exe` and `taskmgr.exe` are built-in Windows programs, so they look like obvious false-positive filters. In this data, both were used to dump LSASS.

**2. `UNKNOWN(...)` in CallTrace is a strong signal.** It means the code requesting access was running from memory with no file on disk behind it (reflective loading, unpacking, or injection). It appeared in the `m.exe` hit and one PowerShell hit.

**3. CallTrace isn't always detailed.** Three older PowerShell hits had only two frames (`ntdll` → `KERNELBASE`), so CallTrace-based logic can't always be relied on.

## Tuning experiment: the "obvious" filter

I tested excluding `services.exe` and `taskmgr.exe` by name:

| Version | Hits | Real attacks missed |
|---------|------|---------------------|
| No filter | 26 | 0 |
| Naive filter (`services.exe`, `taskmgr.exe`) | 23 | **3** |

All 3 removed hits were confirmed attacks, so I did **not** keep this filter. In a real environment, I would only filter a verified source using precise evidence (exact path plus expected CallTrace modules), never on process name alone.

## Benchmark against a SigmaHQ community rule

I ran SigmaHQ's **LSASS Memory Dump** rule (`proc_access_win_lsass_memdump.yml`) on the same 278 files.

**Result: 0 hits.** I isolated the cause one condition at a time:

| Test | Hits |
|------|------|
| Full rule as published | 0 |
| Main selection only (filters removed) | 16 |
| Selection + `filter_main_system_user` (by wildcard or exact name) | 0 |

The filter excludes processes running as SYSTEM using the `SourceUser` field. **All 16 matching events lacked `SourceUser`**, because older Sysmon versions didn't record it, and in Chainsaw the missing field caused every event to be excluded. The rule's logic is sound, but on this data it fails silently.

Comparing on the main selection only, SigmaHQ's 16 hits are a subset of my 26. It missed 10 attacks (Mimikatz, three PowerShell hits, Python, `m.exe`, MalSeclogon, PPLdump ×2, one `services.exe`) because it deliberately excludes the noisier `0x1010`, `0x1410`, and `0x1000` masks.

**Takeaway:** the community rule trades coverage for fewer false positives in production. Mine trades the opposite way, which suits hunting. Both results show why rules must be tested against your own environment's actual data.

## False positives and tuning

No false positives appeared, but this dataset contains only attack activity, so it can't measure false positives. In a real environment, expect antivirus and EDR agents, backup and monitoring tools, and some system processes to access LSASS with `0x1010`, `0x1410`, and `0x1400`. Tuning should rely on exact file paths, code signatures, and expected CallTrace modules, validated against a baseline of normal activity.

## Known gaps

- Requires Sysmon Event ID 10 to be configured to log access to `lsass.exe`.
- Credential theft that never opens a handle to LSASS from user mode (kernel drivers, or reading memory snapshots or hibernation files) produces no Event ID 10.
- Access masks outside the list are not detected.

## Follow-up detection ideas

- High-confidence rule: LSASS access where CallTrace contains `UNKNOWN(`
- Non-SYSTEM accounts accessing LSASS, once `SourceUser` is available (newer Sysmon), as suggested in the Splunk research
- Correlating LSASS access with a new `.dmp` file being created shortly after

## References

- [MITRE ATT&CK T1003.001](https://attack.mitre.org/techniques/T1003/001/)
- [Splunk: You Bet Your Lsass: Hunting LSASS Access](https://www.splunk.com/en_us/blog/security/you-bet-your-lsass-hunting-lsass-access.html)
- [Microsoft: Process Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [SigmaHQ rules](https://github.com/SigmaHQ/sigma)
- [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
- [Chainsaw](https://github.com/WithSecureOpenSource/chainsaw)
