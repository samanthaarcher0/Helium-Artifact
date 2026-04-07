#!/usr/bin/env python3
"""Parse a log file and output a row for the results table:
Optimization | Runtime (s) | # SMT queries | Time per SMT query (s) | # MC queries | Time per MC query (s)
"""

import re
import sys
import os


def parse_optimization_name(filepath):
    """Extract optimization name from the results directory path in the log."""
    # Look for results_<name>_<date> pattern in the log
    with open(filepath, 'r') as f:
        text = f.read()

    # Try to get it from "Outputs written to dir:" line
    match = re.search(r"Outputs written to dir:.*?results_(.+?)_\d{4}-\d{2}-\d{2}", text)
    if match:
        return match.group(1)

    # Fallback: try the filename itself
    basename = os.path.basename(filepath)
    match = re.match(r"out_(.+?)\.log", basename)
    if match:
        return match.group(1)

    return os.path.basename(filepath)


def parse_log(filepath):
    with open(filepath, 'r') as f:
        text = f.read()

    runtime_match = re.search(r"Total runtime:\s*([0-9.]+)", text)
    queries_match = re.search(r"Number of queries:\s*(\d+)", text)
    avg_smt_match = re.search(r"Average SMT query time:\s*[0-9./]+=([0-9.eE+-]+)", text)
    num_paths_match = re.search(r"Number of paths:\s*(\d+)", text)
    avg_mc_match = re.search(r"Average model count time:\s*[0-9./]+=([0-9.eE+-]+)", text)

    optimization = parse_optimization_name(filepath)
    runtime = float(runtime_match.group(1)) if runtime_match else None
    num_smt = int(queries_match.group(1)) if queries_match else None
    time_per_smt = float(avg_smt_match.group(1)) if avg_smt_match else None
    num_mc = int(num_paths_match.group(1)) if num_paths_match else None
    time_per_mc = float(avg_mc_match.group(1)) if avg_mc_match else None

    return {
        "optimization": optimization,
        "runtime": runtime,
        "num_smt": num_smt,
        "time_per_smt": time_per_smt,
        "num_mc": num_mc,
        "time_per_mc": time_per_mc,
    }


def format_row(d):
    def fmt(v, decimals=4):
        if v is None:
            return "N/A"
        if isinstance(v, int):
            return str(v)
        return f"{v:.{decimals}f}"

    return (
        f"{d['optimization']:<30s} | "
        f"{fmt(d['runtime'], 2):>10s} | "
        f"{fmt(d['num_smt']):>13s} | "
        f"{fmt(d['time_per_smt'], 6):>18s} | "
        f"{fmt(d['num_mc']):>13s} | "
        f"{fmt(d['time_per_mc'], 4):>22s}"
    )


def header():
    return (
        f"{'Optimization':<30s} | "
        f"{'Runtime (s)':>10s} | "
        f"{'# SMT queries':>13s} | "
        f"{'Time per SMT query (s)':>18s} | "
        f"{'# MC queries':>13s} | "
        f"{'Time per MC query (s)':>22s}"
    )


def separator():
    return (
        f"{'-'*30}-+-"
        f"{'-'*11}-+-"
        f"{'-'*13}-+-"
        f"{'-'*22}-+-"
        f"{'-'*13}-+-"
        f"{'-'*22}"
    )


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <logfile> [logfile2 ...]")
        sys.exit(1)

    print(header())
    print(separator())
    for logfile in sys.argv[1:]:
        d = parse_log(logfile)
        print(format_row(d))
