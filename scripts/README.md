# summarize_hits.py

Summarizes Chainsaw hunt results from a CSV file: counts hits per rule (or any other column) and prints them highest first.

## Usage

```bash
# Count hits per rule (default)
python3 scripts/summarize_hits.py results/all/sigma.csv

# Count hits per host
python3 scripts/summarize_hits.py results/all/sigma.csv --column Computer

# Print a Markdown table (used for the main README)
python3 scripts/summarize_hits.py results/all/sigma.csv --markdown
```

## Example output

| detections | Hits |
|------|------|
| Suspicious LSASS Memory Access | 26 |
| Scheduled Task Created via Command Line | 7 |
| Encoded PowerShell Command Line | 1 |
| **Total** | **34** |

## How it evolved

Built in three steps, each a separate commit:

1. Basic version: count hits per rule
2. `--column`: count by any CSV column, with a friendly error listing valid columns
3. `--markdown`: print a ready-to-paste table

Python standard library only (`argparse`, `csv`, `collections.Counter`); no installs needed.
