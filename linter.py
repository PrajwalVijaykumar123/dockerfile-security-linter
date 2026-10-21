#!/usr/bin/env python3
"""
Dockerfile Security Linter

Static analysis of a Dockerfile for common security misconfigurations:
running as root, unpinned ':latest' base images, secrets baked into
layer history via ENV/ARG, risky ADD usage, apt-get layers that bloat
the image with cached package indexes, sensitive EXPOSEd ports, and
curl-pipe-to-shell patterns that turn a compromised download into
arbitrary build-time code execution.

Usage:
    python3 linter.py Dockerfile
    python3 linter.py Dockerfile --json report.json
    python3 linter.py Dockerfile --fail-on high
"""

import sys
import json
import argparse

from parser import parse_dockerfile
from rules import run_all_rules

SEVERITY_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def lint(path):
    instructions = parse_dockerfile(path)
    findings = run_all_rules(instructions)
    return instructions, findings


def print_report(path, instructions, findings):
    print(f"\n{path}  ({len(instructions)} instruction(s) parsed)")
    if not findings:
        print("  No findings.")
        return
    for f in findings:
        location = f"L{f.line}" if f.line else "  -"
        print(f"  [{f.severity:<6}] {f.rule_id} {location:<5} {f.message}")


def main():
    parser = argparse.ArgumentParser(description="Static security linter for Dockerfiles.")
    parser.add_argument("dockerfile", help="Path to the Dockerfile to lint")
    parser.add_argument("--json", metavar="FILE", help="Also write a JSON report to FILE")
    parser.add_argument("--fail-on", choices=["low", "medium", "high", "any", "none"], default="high",
                         help="Minimum severity that causes a non-zero exit code (default: high)")
    args = parser.parse_args()

    try:
        instructions, findings = lint(args.dockerfile)
    except OSError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)

    print_report(args.dockerfile, instructions, findings)

    if args.json:
        with open(args.json, "w") as f:
            json.dump({
                "dockerfile": args.dockerfile,
                "instruction_count": len(instructions),
                "findings": [{"severity": fd.severity, "rule_id": fd.rule_id, "line": fd.line, "message": fd.message} for fd in findings],
            }, f, indent=2)
        print(f"\nJSON report written to {args.json}")

    if args.fail_on == "none":
        sys.exit(0)
    if args.fail_on == "any":
        sys.exit(1 if findings else 0)

    threshold = SEVERITY_RANK[args.fail_on.upper()]
    worst = max((SEVERITY_RANK[f.severity] for f in findings), default=-1)
    sys.exit(1 if worst >= threshold else 0)


if __name__ == "__main__":
    main()
