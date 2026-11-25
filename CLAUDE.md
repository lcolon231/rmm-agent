## Agent skills

### Issue tracker

Issues and specs live in GitHub Issues for lcolon231/rmm-agent (via `gh`). See `docs/agents/issue-tracker.md`.

### Triage labels

Default five-role vocabulary: needs-triage, needs-info, ready-for-agent, ready-for-human, wontfix. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: `GLOSSARY.md` and `docs/adr/` at the repo root, created as needed. See `docs/agents/domain.md`.

## Server tools

Run server tests and lint with the venv interpreter, not the system Python: `server/.venv/Scripts/python.exe -m pytest` and `-m ruff check app tests scripts alembic` (from `server/`). Set the venv up as `server/README.md` describes.

## Live verification

End-to-end or manual verification against a running server and dashboard: `docs/LOCAL-E2E.md`.
