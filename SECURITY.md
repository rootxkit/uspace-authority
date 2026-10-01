# Security policy

`uspace-authority` is the competent authority's system of the Georgian
U-space rebuild: it holds the registry of operators, UAS and remote
pilots, the audit log and the ecosystem token issuer. Report a
vulnerability privately to the repository owner through GitHub's private
vulnerability reporting on this repository (Security tab, "Report a
vulnerability"). Do not open a public issue.

We acknowledge a report within 7 days and aim to publish a fix, or an
agreed statement, within 90 days of the report.

Scope: everything in this repository, including the images built from
it. Out of scope: `uspace-core` (report there: a judgement lives there
once) and the sibling systems, each with its own policy.

This repository is public. No secret, key, certificate, token, real
hostname or real registry data is ever committed, including test keys:
keys are generated at test time, fixtures use `GEO-TEST-*` and `TEST*`
values, and `gitleaks` runs in CI. Real configuration lives in the
private deployment repository.
