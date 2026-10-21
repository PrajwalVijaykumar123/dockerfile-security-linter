# Dockerfile Security Linter

Static analysis of a Dockerfile for common security misconfigurations — the same category of checks tools like `hadolint` and Docker Scout run, built from scratch to parse Dockerfile instructions and reason about each one directly rather than treating linting as a black box.

## What This Project Does

Eleven rules, each checking a specific, well-documented Dockerfile anti-pattern:

| Rule | Severity | Checks for |
|------|----------|-------------|
| DL-001 | HIGH | No `USER` instruction (or final `USER` is `root`) — container runs as root |
| DL-002 | MEDIUM | `FROM` with no tag, or explicit `:latest` — not reproducible |
| DL-003 | HIGH | `ENV`/`ARG` keys that look like secrets (`API_SECRET`, `DB_PASSWORD`, etc.) — baked into image layer history, extractable via `docker history` even after a later layer "removes" them |
| DL-004 | MEDIUM | `ADD` fetching a remote URL — no checksum verification |
| DL-005 | LOW | `ADD` used for a plain file instead of `COPY` |
| DL-006 | LOW | `apt-get install` without cleaning `/var/lib/apt/lists` in the same layer |
| DL-007 | LOW | `apt-get install` missing `-y` — hangs in automated builds |
| DL-008 | MEDIUM | `EXPOSE` on a sensitive port (SSH, RDP, database ports) |
| DL-009 | INFO | No `HEALTHCHECK` instruction |
| DL-010 | LOW | `sudo` inside a `RUN` step (usually a copy-pasted host command; `RUN` is already root) |
| DL-011 | HIGH | `curl \| sh` / `wget \| bash` pattern — a compromised or MITM'd download becomes arbitrary build-time code execution |

## Why the secrets-in-ENV check matters more than it looks

A Dockerfile that sets a secret with `ENV` and removes it in a later `RUN` step looks clean in the final `docker inspect` output — but every intermediate layer is still part of the image and still downloadable. `docker history --no-trunc` (or just unpacking the image's layer tarballs) recovers it. This is one of the most common real-world image-security findings, and it's invisible unless a linter looks at *every* instruction, not just the final image state.

## Example Output

```
test_fixtures/bad.Dockerfile  (10 instruction(s) parsed)
  [HIGH  ] DL-001   -   No USER instruction found - the container will run as root by default. ...
  [HIGH  ] DL-003 L2    ENV API_SECRET looks like a secret baked into the image layer history - ...
  [HIGH  ] DL-011 L5    Piping a downloaded script straight into a shell - the build has no way ...
  [MEDIUM] DL-002 L1    FROM ubuntu has no tag - defaults to ':latest', which is not reproducible ...
  [MEDIUM] DL-008 L8    EXPOSE 22 (SSH) - confirm this is intentional for a container image; ...
  ...
```

(Real output — the linter actually parsing and flagging the deliberately-bad test fixture, not a mocked result.)

## Tech Stack

- Python 3.11, standard library only (`re`, `json`, `argparse`)

## Setup

```bash
python3 linter.py Dockerfile
python3 linter.py Dockerfile --fail-on medium     # low/medium/high/any/none
python3 linter.py Dockerfile --json report.json
```

Exit code reflects the `--fail-on` threshold (default `high`) — suitable for a CI check that shouldn't block a build over an INFO-level suggestion.

## Testing

`test_fixtures/bad.Dockerfile` deliberately contains every anti-pattern this tool checks for; `test_fixtures/good.Dockerfile` is a realistic, properly-hardened Dockerfile (non-root user, pinned base image version, apt cache cleanup, a HEALTHCHECK) with zero findings:

```bash
sh test_fixtures/run_test.sh
```

This runs the real `linter.py` against both real files and checks that every one of the eleven rules fires exactly where expected on the bad file, that the good file produces zero findings, and that multi-line `RUN` instructions (joined with trailing `\`) are correctly parsed as a single instruction rather than being split and mis-analyzed.

## Architecture

```
Dockerfile
        |
        v
parser.py: line-by-line parse, joining backslash-continued lines,
            into Instruction(cmd, args, line_number) objects
        |
        v
rules.py: 11 independent rule functions, each scanning the full
           instruction list for one specific pattern
        |
        v
Findings ranked HIGH -> MEDIUM -> LOW -> INFO, by line number
        |
        v
Console report + optional JSON report; exit code reflects --fail-on threshold
```

## Project Structure

```
dockerfile-security-linter/
├── linter.py                    # CLI: parse, run rules, report
├── parser.py                     # Dockerfile instruction parser (handles line continuations)
├── rules.py                      # The 11 security checks
├── requirements.txt                # No external deps - stdlib only
└── test_fixtures/
    ├── bad.Dockerfile            # Deliberately contains every anti-pattern checked for
    ├── good.Dockerfile           # A properly-hardened Dockerfile - zero findings
    └── run_test.sh                 # Runs linter.py against both, verifies real findings
```

## What I Learned

- "Removed in a later layer" is a common but false sense of security in Docker images — every layer is immutable and independently extractable, so a secret set and then unset is still fully recoverable. This is the single most-cited real-world Dockerfile security finding in tools like this one, and it only shows up if a linter inspects the full instruction history rather than the final resolved state
- `ADD`'s extra behaviors (URL fetching, automatic archive extraction) are exactly the behaviors that make it the wrong default choice almost all of the time — `COPY` being "boring" (does one thing, copies a file) is the security-relevant property, not a limitation
- A build-time `curl | sh` is a software-supply-chain risk in exactly the same shape as a dependency-confusion attack: the build process executes code from a source it didn't cryptographically verify, just at a different point in the pipeline than a package manager would be

## Next Steps

- Multi-stage build awareness — track which `COPY --from=<stage>` references are valid, and whether secrets set in an early stage leak into the final one
- A `.dockerignore` presence/content check, since a missing or incomplete one can copy `.git`, `.env`, or other sensitive local files into the build context
- Resolve `ARG`-based image tags where possible, to catch `FROM ${BASE_IMAGE}` cases that resolve to `:latest` at build time
- An auto-fix mode that rewrites the obviously mechanical fixes (adding `-y`, appending the apt cleanup command) and leaves a diff for review
