#!/bin/sh
# Runs the real linter.py against two real Dockerfiles - one deliberately
# riddled with issues, one deliberately clean - and checks the actual
# findings produced, no mocking.
set -e
cd "$(dirname "$0")/.."

echo "== bad.Dockerfile: expect every rule category to fire =="
set +e
python3 linter.py test_fixtures/bad.Dockerfile --fail-on high > /tmp/dsl_bad.txt 2>&1
EXIT_BAD=$?
set -e
cat /tmp/dsl_bad.txt

grep -q "DL-001" /tmp/dsl_bad.txt && echo "PASS: missing USER (runs as root) flagged" || { echo "FAIL"; exit 1; }
grep -q "DL-002" /tmp/dsl_bad.txt && echo "PASS: unpinned ':latest' base image flagged" || { echo "FAIL"; exit 1; }
grep -q "DL-003.*API_SECRET" /tmp/dsl_bad.txt && echo "PASS: ENV secret flagged" || { echo "FAIL"; exit 1; }
grep -q "DL-003.*DB_PASSWORD" /tmp/dsl_bad.txt && echo "PASS: ARG secret flagged" || { echo "FAIL"; exit 1; }
grep -q "DL-004" /tmp/dsl_bad.txt && echo "PASS: ADD-from-URL flagged" || { echo "FAIL"; exit 1; }
grep -q "DL-006" /tmp/dsl_bad.txt && echo "PASS: apt-get cache not cleaned flagged" || { echo "FAIL"; exit 1; }
grep -q "DL-007" /tmp/dsl_bad.txt && echo "PASS: apt-get install missing -y flagged" || { echo "FAIL"; exit 1; }
grep -q "DL-008.*SSH" /tmp/dsl_bad.txt && echo "PASS: sensitive port 22 flagged" || { echo "FAIL"; exit 1; }
grep -q "DL-008.*MySQL" /tmp/dsl_bad.txt && echo "PASS: sensitive port 3306 flagged" || { echo "FAIL"; exit 1; }
grep -q "DL-009" /tmp/dsl_bad.txt && echo "PASS: missing HEALTHCHECK noted" || { echo "FAIL"; exit 1; }
grep -q "DL-010" /tmp/dsl_bad.txt && echo "PASS: sudo-in-RUN flagged" || { echo "FAIL"; exit 1; }
grep -q "DL-011" /tmp/dsl_bad.txt && echo "PASS: curl-pipe-to-shell flagged" || { echo "FAIL"; exit 1; }
[ "$EXIT_BAD" = "1" ] && echo "PASS: exit code 1 (HIGH findings present)" || { echo "FAIL: expected exit 1, got $EXIT_BAD"; exit 1; }

echo
echo "== good.Dockerfile: expect zero findings, exit 0 =="
set +e
python3 linter.py test_fixtures/good.Dockerfile --fail-on high > /tmp/dsl_good.txt 2>&1
EXIT_GOOD=$?
set -e
cat /tmp/dsl_good.txt
grep -q "No findings." /tmp/dsl_good.txt && echo "PASS: clean Dockerfile produces zero findings" || { echo "FAIL: expected no findings"; exit 1; }
[ "$EXIT_GOOD" = "0" ] && echo "PASS: exit code 0 on clean Dockerfile" || { echo "FAIL: expected exit 0, got $EXIT_GOOD"; exit 1; }

echo
echo "== Line-continuation parsing: multi-line RUN must become a single instruction =="
python3 -c "
from parser import parse_dockerfile
instructions = parse_dockerfile('test_fixtures/good.Dockerfile')
run_instrs = [i for i in instructions if i.cmd == 'RUN']
assert any('rm -rf /var/lib/apt/lists' in i.args for i in run_instrs), 'multi-line RUN was not joined correctly'
print('PASS: multi-line RUN instruction correctly joined into one instruction')
"

rm -f /tmp/dsl_bad.txt /tmp/dsl_good.txt
echo
echo "All tests passed."
