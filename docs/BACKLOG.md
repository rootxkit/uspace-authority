# Backlog

Ranked table of open items. Source is not recorded in the list this was built from.

| # | Severity (high/medium/low) | Item | Where (file:line if given) | Source (the review that found it) |
|---|---|---|---|---|
| 1 | medium | internal/cisp/direct.go:455-458: baseMayHold keeps ends indefinitely after a restart until the first pull; the branch is untested. | internal/cisp/direct.go:453 (baseMayHold; moved from 455-458) | not recorded |
| 2 | medium | direct.go:597: an active direct restriction past ends_at is dropped after the keep period while the CISP may hold an older active row. | internal/cisp/direct.go:597-598 (moved slightly) | not recorded |
| 3 | low | Kept ends count towards CIS_DIRECT_MAX. | - | not recorded |
| 4 | low | web outline.ts: debounce the circle-outline requests, and retry on network failure. | web/src/zones/editor/outline.ts | not recorded |
| 5 | low | The openapi maximum: 1000000 / ±89 values duplicate Go constants; pin them in a contract test. | api/openapi.yaml | not recorded |
| 6 | low | No axe pass covers /zones/new with DrawLayer. | - | not recorded |
| 7 | low | The picture-ws police allow-list gap (documented in the runbook). | - | not recorded |
