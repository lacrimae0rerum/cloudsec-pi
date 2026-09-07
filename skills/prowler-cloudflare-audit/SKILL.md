---
name: prowler-cloudflare-audit
description: Run an authorised read-only Cloudflare posture and compliance assessment with Prowler CLI through cloudsec-pi. Use for Cloudflare account, zone, DNS or settings security review.
license: MIT
---

# Prowler Cloudflare audit

Assess the Cloudflare resources visible to the operator's native Prowler credentials and keep provider evidence local.

## Credential contract

Use a least-privilege Cloudflare API token through `CLOUDFLARE_API_TOKEN`, or the native key and email variables supported by Prowler. Never paste credentials into chat, tool parameters, files in the repository or command flags.

## Procedure

1. Establish that every Cloudflare account and zone visible to the credentials is owned or expressly authorised. If scope is uncertain, stop before invoking Prowler.
2. Call `cloudsec_doctor` with `scanner: "prowler"`. Stop if unavailable and offer `/cloudsec-setup` as a separate human-confirmed preparation workflow.
3. Confirm that the expected Cloudflare credential variable names are present. Discuss names only, never values.
4. Call `cloudsec_prowler` with `provider: "cloudflare"`. Review the environment names and network boundary in the confirmation.
5. Read `metadata` and `report` with `cloudsec_evidence`. Use redacted `stderr` only for operational failure.
6. Return the report below. Preserve Prowler check identifiers and distinguish failed checks from process failure.

## Report

```markdown
# Prowler Cloudflare audit

- Run: <run id>
- Provider: Cloudflare
- Scope: <accounts/zones visible to the authorised credentials>
- Outcome: <completed|failed|cancelled>

## Priority findings

| Severity | Prowler check | Resource | Evidence | Recommended response |
|---|---|---|---|---|

## Compliance view

| Framework or category | Pass | Fail | Unavailable |
|---|---:|---:|---:|

## Coverage and limitations

- Credential scope: <names/permissions, never values>
- Network access: Cloudflare APIs
- Unchecked areas: <explicit gaps>

## Verdict

<provider posture and the three highest-value responses>
```

## Boundaries

- Cloudflare is the only Prowler provider in v0.4.
- Every run is credentialed and networked, so it requires interactive confirmation.
- cloudsec-pi passes no upload or hosted-dashboard flags. It does not enforce network containment.
- Provider reports contain account and resource identifiers. Access them only through `cloudsec_evidence`.

## Avoid

- Running with credentials whose authorised scope is unknown.
- Passing secrets or output flags to the tool.
- Treating Prowler exit code 3 as an operational crash without checking metadata and reports.
- Uploading results to Prowler Cloud or another service.
