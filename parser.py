"""
A small, deliberately non-exhaustive Dockerfile parser: enough to pull
out each instruction, its arguments, and its line number for the
security rules to inspect. Not a full Dockerfile grammar (doesn't
resolve ARG substitution or multi-stage build target names) - good
enough for static security analysis.
"""

import re


class Instruction:
    def __init__(self, cmd, args, line):
        self.cmd = cmd      # e.g. "FROM", "RUN", "USER"
        self.args = args    # everything after the instruction keyword
        self.line = line

    def __repr__(self):
        return f"<{self.cmd} {self.args!r} (line {self.line})>"


def parse_dockerfile(path_or_lines):
    if isinstance(path_or_lines, str):
        with open(path_or_lines) as f:
            raw_lines = f.readlines()
    else:
        raw_lines = path_or_lines

    instructions = []
    buffer = ""
    start_line = None

    for lineno, raw in enumerate(raw_lines, start=1):
        line = raw.rstrip("\n")
        stripped = line.strip()

        if not buffer and (not stripped or stripped.startswith("#")):
            continue

        if not buffer:
            start_line = lineno

        # Line-continuation: a trailing backslash joins with the next line.
        if stripped.endswith("\\"):
            buffer += stripped[:-1] + " "
            continue

        buffer += stripped
        full_line = buffer
        buffer = ""

        match = re.match(r"^([A-Za-z]+)\s*(.*)$", full_line)
        if not match:
            continue
        cmd, args = match.group(1).upper(), match.group(2)
        instructions.append(Instruction(cmd, args, start_line))

    return instructions
