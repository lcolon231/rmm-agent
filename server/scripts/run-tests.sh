#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Run targeted server tests and exit with pytest's own status.
#
#   server/scripts/run-tests.sh tests/test_tenant_scope.py tests/test_audit_views.py
#
# The full log goes to $RUN_TESTS_LOG (default: a temp file); only the failure
# list and the summary line are printed. Because nothing is piped, the exit code
# is pytest's, so a background run reports failure as failure.
#
# Interpreter: $PYTHON if set, else the repo's shared .venv-server-tests (found
# from the git common dir, so it works from the main checkout and from any
# worktree), else `python`. Extra pytest flags pass straight through.
set -u

server_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$server_dir" || exit 2

if [ -z "${PYTHON:-}" ]; then
  repo_root="$(cd "$(git rev-parse --git-common-dir)/.." && pwd)"
  for candidate in \
    "$repo_root/.venv-server-tests/Scripts/python.exe" \
    "$repo_root/.venv-server-tests/bin/python"; do
    if [ -x "$candidate" ]; then PYTHON="$candidate"; break; fi
  done
fi
PYTHON="${PYTHON:-python}"

if [ "$#" -eq 0 ]; then
  echo "usage: $0 <test files or pytest args...>" >&2
  exit 2
fi

log="${RUN_TESTS_LOG:-$(mktemp "${TMPDIR:-/tmp}/run-tests.XXXXXX.log")}"

PYTHONPATH=. "$PYTHON" -m pytest -q -p no:cacheprovider --tb=short \
  -W ignore::DeprecationWarning "$@" > "$log" 2>&1
status=$?

grep -E '^(FAILED|ERROR) ' "$log"
tail -n 1 "$log"
echo "pytest exit=$status  log=$log"
exit "$status"
