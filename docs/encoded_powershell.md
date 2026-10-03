# Encoded PowerShell Command Line

- **Rule file:** `rules/encoded_powershell.yml`
- **MITRE ATT&CK:** [T1059.001 Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- **Log source:** Windows process creation (Sysmon Event ID 1 / Security Event ID 4688)
- **Level:** medium

## What it detects

PowerShell (`powershell.exe` or `pwsh.exe`) launched with an encoded command (`-enc` or `-EncodedCommand`). Attackers encode commands to hide script content from casual review and from simple keyword-based 
detections.

## Logic

Alert when the process image ends with `powershell.exe` or `pwsh.exe` **and** the command line contains one of ` -enc `, ` -EncodedCommand `, ` -e `, ` -ec `, or ` -en ` (case-insensitive). The spaces around each flag limit the match to the flag itself, not any text that happens to contain those letters.

## Testing

- **Tool:** [Chainsaw](https://github.com/WithSecureOpenSource/chainsaw) v2.16.5 with the `sigma-event-logs-all.yml` mapping
- **Data:** [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) (public Windows attack logs)

| Test run | Files | Hits | True positives | False positives | Notes |
|----------|-------|------|----------------|-----------------|-------|
| Targeted: Execution folder | 34 | 0 | 0 | 0 | No PowerShell launched with `-enc` in this folder |
| Full sample set | 278 | 1 | 1 | 0 | See finding below |
| Full sample set (after tuning) | 278 | 1 | 1 | 0 | Added `-e`, `-ec`, `-en`; no new hits or false positives. The samples don't contain these variants, so the new patterns are untested against true positives |

```bash
./chainsaw hunt "../EVTX-ATTACK-SAMPLES" \
  -s rules/encoded_powershell.yml \
  --mapping mappings/sigma-event-logs-all.yml
```

## Finding: web server launching encoded PowerShell

| Field | Value |
|-------|-------|
| Host / record | IEWIN7, record ID 5875 (2019-05-27) |
| Parent process | `C:\Windows\System32\inetsrv\w3wp.exe` (IIS worker process) |
| User / integrity | `IIS APPPOOL\DefaultAppPool`, High |
| Command line | `powershell.exe -nop -noni -enc <Base64>` |

I decoded the Base64 payload (PowerShell encodes as UTF-16LE):

```bash
base64 -d b64.txt | iconv -f UTF-16LE -t UTF-8
```

The decoded script:
1. Reads two files from a random-named folder, `C:\Windows\Temp\6jrxk3\`
2. XOR-decrypts both files with a hardcoded key
3. Runs the combined result in memory with `Invoke-Expression` (`iex`)
4. Deletes one of the files to cover its tracks

**Verdict: true positive.** A web server process spawning hidden PowerShell that decrypts and runs a payload in memory, then removes evidence, is consistent with a web shell or an exploited web application delivering a staged loader.

Related techniques: T1027 (Obfuscated Files or Information), T1140 (Deobfuscate/Decode Files or Information), T1070.004 (Indicator Removal: File Deletion), T1505.003 (Web Shell, suspected entry point).

## Benchmark against a SigmaHQ community rule

I ran SigmaHQ's **PowerShell Base64 Encoded IEX Cmdlet** rule on the same 278 files. It found 2 events my rule missed, and it did not detect my IIS finding.

In both of its hits, `wscript.exe` ran a VBScript disguised as `c:\windows\temp\icon.ico` and passed PowerShell a command that decodes Base64 inline with `[System.Convert]::FromBase64String` and runs it with `IEX`. My rule missed these because no `-enc` flag is used and the logged process is `wscript.exe`.

**Takeaway:** the two rules cover different encoding methods. Neither alone covers both, which is why defenders layer detections.

## False positives and tuning

No false positives appeared in the sample data. In a real environment, legitimate encoded commands can come from admin scripts, software deployment agents, and management tools. I would baseline known-good parent processes, users, and script paths, and filter only verified sources, never on command content alone.

## Known evasions and gaps

- **Other abbreviations and obfuscation:** PowerShell also accepts longer partial forms such as `-enco` or `-encodedcomm`, and attackers can insert characters to break simple string matches. The rule now covers `-e`, `-ec`, `-en`, `-enc`, and `-EncodedCommand`, but not every variant.
- **Inline decoding:** `FromBase64String` + `IEX` without `-enc` (found in the benchmark above).
- **Renamed binary:** if `powershell.exe` is copied and renamed, the `Image` check fails. Matching on `OriginalFileName` (`PowerShell.EXE`) would close this gap.
- **No PowerShell process:** PowerShell can run inside other host processes, which this process-creation rule cannot see.

## Follow-up detection ideas

- Web server processes (such as `w3wp.exe`) spawning PowerShell or `cmd.exe`
- PowerShell script block logging (Event ID 4104) containing `-bxor` together with `IEX` or `FromBase64String`
- Adding `OriginalFileName` matching to catch renamed PowerShell binaries

## References

- [MITRE ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [SigmaHQ rules](https://github.com/SigmaHQ/sigma)
- [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
- [Chainsaw](https://github.com/WithSecureOpenSource/chainsaw)
