---
name: Bug report
about: Report reproducible incorrect behavior that is not a private vulnerability
title: "bug: "
labels: ["type:bug"]
assignees: []
---

## Summary

<!-- What happened, and what should have happened? -->

## Why it matters

<!-- Include operational/security impact and affected users/endpoints. -->

## Reproduction

1.

## Environment

- Server revision/version:
- Agent version:
- Windows version (if applicable):
- Deployment topology:
- Database:

## Scope

-

## Out of scope

-

## Technical considerations

<!-- Suspected components, APIs/contracts, schemas/migrations, security
boundaries, compatibility, and diagnostic evidence. Redact secrets. -->

## Acceptance criteria

- [ ] The reproduction fails before the fix and passes after it.
- [ ] The expected behavior is covered by regression tests.
- [ ] Related failure paths do not regress.

## Testing requirements

- [ ] Unit/integration regression test
- [ ] Windows reproduction when endpoint/installer behavior is affected
- [ ] Security negative test when a trust boundary is affected

## Documentation requirements

- [ ] Relevant behavior, limitation, or runbook is updated.

## Dependencies

- None identified.
