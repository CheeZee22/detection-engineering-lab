import argparse
import csv
import sys
from collections import Counter


def count_column(path, column):
    counts = Counter()
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if column not in reader.fieldnames:
            print(f"Column '{column}' not found. Available columns: {', '.join(reader.fieldnames)}")
            sys.exit(1)
        for row in reader:
            counts[row[column]] += 1
    return counts


def print_plain(counts, column):
    total = sum(counts.values())
    print(f"{'Count':>5}  {column}")
    print("-" * 40)
    for value, count in counts.most_common():
        print(f"{count:>5}  {value}")
    print("-" * 40)
    print(f"{total:>5}  Total")

def print_markdown(counts, column):
    print(f"| {column} | Hits |")
    print("|------|------|")
    for value, count in counts.most_common():
        print(f"| {value} | {count} |")
    print(f"| **Total** | **{sum(counts.values())}** |")

def main():
    parser = argparse.ArgumentParser(description="Summarize Chainsaw hunt results from a CSV file.")
    parser.add_argument("csv_path", help="path to a Chainsaw CSV output file")
    parser.add_argument("--column", default="detections", help="column to count by (default: detections)")
    parser.add_argument("--markdown", action="store_true", help="print a Markdown table instead of plain text")
    args = parser.parse_args()

    counts = count_column(args.csv_path, args.column)
    if args.markdown:
        print_markdown(counts, args.column)
    else:
        print_plain(counts, args.column)


if __name__ == "__main__":
    main()
