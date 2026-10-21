"""
The actual Dockerfile security checks - each rule takes the fully
parsed instruction list and returns a list of Finding objects. Kept
separate from parsing and the CLI so each rule can be unit-tested with
a plain list of instructions.
"""

import re

SECRET_KEY_HINTS = (
    "password", "passwd", "secret", "api_key", "apikey", "access_key",
    "private_key", "aws_secret", "token", "auth_token",
)

SENSITIVE_PORTS = {22: "SSH", 23: "Telnet", 3389: "RDP", 5432: "PostgreSQL",
                    3306: "MySQL", 6379: "Redis", 27017: "MongoDB"}


class Finding:
    def __init__(self, severity, rule_id, line, message):
        self.severity = severity  # "HIGH" | "MEDIUM" | "LOW" | "INFO"
        self.rule_id = rule_id
        self.line = line
        self.message = message

    def __repr__(self):
        return f"<{self.severity} {self.rule_id} L{self.line}: {self.message}>"


def check_missing_user(instructions):
    """No USER instruction at all (or only USER root) anywhere in the
    file -> the container runs as root by default."""
    user_instructions = [i for i in instructions if i.cmd == "USER"]
    if not user_instructions:
        return [Finding("HIGH", "DL-001", 0,
                "No USER instruction found - the container will run as root by default. "
                "Add 'USER <non-root>' after installing dependencies.")]

    last_user = user_instructions[-1].args.strip()
    if last_user in ("root", "0"):
        return [Finding("HIGH", "DL-001", last_user and user_instructions[-1].line,
                f"Final USER is '{last_user}' - the container runs as root. Switch to a non-root user before CMD/ENTRYPOINT.")]
    return []


def check_latest_tag(instructions):
    findings = []
    for i in instructions:
        if i.cmd != "FROM":
            continue
        image = i.args.split()[0]
        if ":" not in image:
            findings.append(Finding("MEDIUM", "DL-002", i.line,
                f"FROM {image} has no tag - defaults to ':latest', which is not reproducible and can silently change over time."))
        elif image.endswith(":latest"):
            findings.append(Finding("MEDIUM", "DL-002", i.line,
                f"FROM {image} explicitly pins ':latest' - same reproducibility problem as no tag at all. Pin a specific version."))
    return findings


def check_secrets_in_env_arg(instructions):
    findings = []
    for i in instructions:
        if i.cmd not in ("ENV", "ARG"):
            continue
        key_part = i.args.split("=")[0].split()[0] if i.args else ""
        key_lower = key_part.lower()
        if any(hint in key_lower for hint in SECRET_KEY_HINTS):
            findings.append(Finding("HIGH", "DL-003", i.line,
                f"{i.cmd} {key_part} looks like a secret baked into the image layer history - "
                f"anyone with the image can extract it with 'docker history' even if a later layer removes it. "
                f"Use build secrets (--mount=type=secret) or inject at runtime instead."))
    return findings


def check_add_vs_copy(instructions):
    findings = []
    for i in instructions:
        if i.cmd != "ADD":
            continue
        first_arg = i.args.split()[0] if i.args else ""
        if first_arg.startswith(("http://", "https://")):
            findings.append(Finding("MEDIUM", "DL-004", i.line,
                "ADD fetching a remote URL directly - no checksum verification, and the file isn't cleaned up "
                "from any intermediate layer. Prefer: curl/wget + checksum verification in a RUN step, or "
                "a multi-stage build."))
        elif not first_arg.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".zip")):
            findings.append(Finding("LOW", "DL-005", i.line,
                "ADD used for a plain file/directory - COPY is more explicit and predictable here. "
                "ADD's extra behavior (auto-extracting archives, fetching URLs) is only useful for archives."))
    return findings


def check_apt_cleanup(instructions):
    findings = []
    for i in instructions:
        if i.cmd != "RUN":
            continue
        has_apt_get_install = re.search(r"\bapt-get\s+install\b", i.args)
        if not has_apt_get_install:
            continue
        if "rm -rf /var/lib/apt/lists" not in i.args:
            findings.append(Finding("LOW", "DL-006", i.line,
                "apt-get install without cleaning /var/lib/apt/lists afterward in the same RUN layer - "
                "bloats the image; package index data persists in the layer even if removed in a later RUN."))
        if re.search(r"\bapt-get\s+install\b(?!.*-y)", i.args) and "-y" not in i.args and "--yes" not in i.args:
            findings.append(Finding("LOW", "DL-007", i.line,
                "apt-get install without -y - will hang waiting for interactive confirmation in automated builds."))
    return findings


def check_sensitive_ports(instructions):
    findings = []
    for i in instructions:
        if i.cmd != "EXPOSE":
            continue
        for token in i.args.split():
            port_str = token.split("/")[0]
            if port_str.isdigit() and int(port_str) in SENSITIVE_PORTS:
                port = int(port_str)
                findings.append(Finding("MEDIUM", "DL-008", i.line,
                    f"EXPOSE {port} ({SENSITIVE_PORTS[port]}) - confirm this is intentional for a container image; "
                    f"administrative/database ports are common lateral-movement targets if exposed further than intended."))
    return findings


def check_missing_healthcheck(instructions):
    has_cmd_or_entrypoint = any(i.cmd in ("CMD", "ENTRYPOINT") for i in instructions)
    has_healthcheck = any(i.cmd == "HEALTHCHECK" for i in instructions)
    if has_cmd_or_entrypoint and not has_healthcheck:
        return [Finding("INFO", "DL-009", 0,
            "No HEALTHCHECK instruction - not a security flaw by itself, but an orchestrator can't detect "
            "a hung or compromised-but-still-running process without one.")]
    return []


def check_sudo_usage(instructions):
    findings = []
    for i in instructions:
        if i.cmd == "RUN" and re.search(r"\bsudo\b", i.args):
            findings.append(Finding("LOW", "DL-010", i.line,
                "RUN using sudo - Dockerfile RUN steps already execute as root (or the current USER) by default; "
                "sudo here usually means a copy-pasted host command, and sudo itself may not even be installed."))
    return findings


def check_curl_pipe_to_shell(instructions):
    findings = []
    for i in instructions:
        if i.cmd != "RUN":
            continue
        if re.search(r"(curl|wget)[^|;&]*\|\s*(sudo\s+)?(sh|bash)\b", i.args):
            findings.append(Finding("HIGH", "DL-011", i.line,
                "Piping a downloaded script straight into a shell - the build has no way to verify the script's "
                "content before executing it, and a compromised or MITM'd download becomes arbitrary code "
                "execution in the image. Download, verify a checksum/signature, then execute."))
    return findings


ALL_RULES = [
    check_missing_user,
    check_latest_tag,
    check_secrets_in_env_arg,
    check_add_vs_copy,
    check_apt_cleanup,
    check_sensitive_ports,
    check_missing_healthcheck,
    check_sudo_usage,
    check_curl_pipe_to_shell,
]


def run_all_rules(instructions):
    findings = []
    for rule in ALL_RULES:
        findings.extend(rule(instructions))
    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    findings.sort(key=lambda f: (severity_order[f.severity], f.line))
    return findings
