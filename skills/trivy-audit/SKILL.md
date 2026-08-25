---
name: trivy-audit
description: Run authorised Trivy audits of project filesystems, infrastructure-as-code, dependencies, secrets or container images through cloudsec-pi. Use for repository, IaC, dependency, secret or image security assessment.
license: MIT
---

# Trivy audit

Produce a concise security assessment from private Trivy evidence without exposing native reports directly in chat.

## Procedure

1. Establish that the filesystem or image is owned or expressly authorised for assessment. State the exact scope.
2. Call `cloudsec_doctor` with `scanner: "trivy"`. Stop if unavailable; give the official installation link from the package README rather than installing it.
3. Choose one target:
   - `fs`: a project-relative path inside the current repository. Use for source, dependencies, secrets, Dockerfiles and IaC.
   - `image`: an explicit container image reference. Explain that registry or Docker socket access may occur and let `cloudsec_trivy` obtain confirmation.
4. Call `cloudsec_trivy`. Do not invoke `trivy` through bash or add free-form flags.
5. Read `metadata` and `report` with `cloudsec_evidence`. Read redacted `stderr` only when the metadata reports failure. Keep reads within the default limit unless a specific finding requires more context.
6. Return the report below. Preserve scanner severity and native finding identifiers. Group duplicate package vulnerabilities by fix rather than repeating prose.

## Report

```markdown
# Trivy audit

- Run: <run id>
- Target: <resolved scope>
- Outcome: <completed|failed|cancelled>
- Evidence: retained locally by cloudsec-pi

## Priority findings

| Severity | Finding | Affected asset | Evidence | Minimum response |
|---|---|---|---|---|

## Coverage and limitations

- Scanners used: <vulnerability/misconfiguration/secret>
- Network access: <database/registry access observed or expected>
- Unchecked areas: <explicit gaps>

## Verdict

<deployable, deployable with accepted risk, or not deployable>
```

## Boundaries

- cloudsec-pi v0.4 scans local project filesystems and images. It does not accept remote Git URLs or Kubernetes targets.
- Trivy may download vulnerability databases. The harness disables its version check and telemetry flags but does not provide network containment.
- Image scans do not include private-registry credential plumbing in v0.4.
- Native evidence can contain project excerpts. Use only `cloudsec_evidence` for model-visible reads.

## Avoid

- Running every scanner when the user asked about one image or directory.
- Treating process exit code as the finding count.
- Copying complete JSON reports into chat.
- Claiming a clean scan proves the target is secure.
