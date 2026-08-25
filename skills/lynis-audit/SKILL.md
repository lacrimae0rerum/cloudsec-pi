---
name: lynis-audit
description: Audit and harden the posture of an authorised local Linux host with Lynis through cloudsec-pi. Use for Linux host configuration, hardening, package, service or compliance review.
license: MIT
---

# Lynis audit

Assess a local Linux host with explicit privilege and coverage statements.

## Procedure

1. Confirm that the local Linux host is owned or expressly authorised. cloudsec-pi v0.4 does not run Lynis remotely.
2. Call `cloudsec_doctor` with `scanner: "lynis"`. Stop if unsupported or unavailable; do not install it automatically.
3. Choose privilege:
   - `privileged: false` for a limited user-level posture review.
   - `privileged: true` for broader host coverage. Explain the root boundary and obtain the tool's confirmation.
4. Call `cloudsec_lynis`. Do not provide profiles, plugin directories, log paths or free-form flags.
5. Read `metadata` and `report` with `cloudsec_evidence`. Use redacted `stderr` only to diagnose a failed run.
6. Interpret `lynis-report.dat` as native key-value evidence. Distinguish warnings, suggestions and operational errors; do not infer findings solely from exit status.
7. Return the report below without applying hardening changes.

## Report

```markdown
# Lynis audit

- Run: <run id>
- Host scope: local Linux host
- Privilege: <user|root>
- Outcome: <completed|failed|cancelled>

## Priority findings

| Priority | Test or control | Evidence | Exposure | Minimum hardening step |
|---|---|---|---|---|

## Coverage gaps

- Tests unavailable without privilege: <summary>
- Platform or package limitations: <summary>

## Verdict

<current posture and the three highest-value hardening actions>
```

## Boundaries

- Root is optional but materially changes coverage.
- The harness sets a private working directory and generated report path; custom Lynis profiles and plugins are outside v0.4.
- Upload features are not used.
- Evidence can contain host inventory and must remain private.

## Avoid

- Treating an unprivileged audit as complete.
- Passing `--profile`, `--plugin-dir`, `--upload` or output paths.
- Applying suggestions automatically.
- Copying the complete host report into chat.
