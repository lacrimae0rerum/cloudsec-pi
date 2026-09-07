---
name: docker-bench-audit
description: Audit an authorised local Linux Docker host against Docker Bench for Security through cloudsec-pi. Use for Docker daemon, container runtime or CIS Docker host checks.
license: MIT
---

# Docker Bench audit

Assess one local Linux Docker host and preserve the native benchmark evidence privately.

## Preconditions

- The host is owned or expressly authorised.
- Pi is running on the Linux Docker host being assessed. Remote and Docker Desktop audits are outside v0.4.
- The operator obtained and reviewed Docker Bench from `https://github.com/docker/docker-bench-security`, using separately confirmed `/cloudsec-setup` or an absolute `DOCKER_BENCH_SECURITY_PATH`. The persisted setup path is used when that environment override is absent.
- cloudsec-pi validates the script path, writable bits and SHA-256. This verifies what was confirmed, not upstream authenticity.

## Procedure

1. State the authorised local host and whether a complete privileged audit is required.
2. Call `cloudsec_doctor` with `scanner: "docker-bench"`. Stop if the platform or configured script is unavailable.
3. Call `cloudsec_docker_bench` with `privileged: true` for the normal benchmark. Use `false` only when the user explicitly accepts reduced coverage.
4. Review the displayed executable, script path and SHA-256 before confirmation. cloudsec-pi uses non-interactive sudo and never handles a password.
5. Read `metadata`, `report` and, if necessary, redacted `stderr` through `cloudsec_evidence`.
6. Return the report below. Separate benchmark failures from checks that could not run.

## Report

```markdown
# Docker Bench audit

- Run: <run id>
- Host scope: local Linux Docker host
- Script identity: <SHA-256 from metadata>
- Outcome: <completed|failed|cancelled>

## Failed checks

| Check | Severity | Observed state | Remediation from benchmark |
|---|---|---|---|

## Not scored or not run

| Check | Reason | Coverage impact |
|---|---|---|

## Verdict

<CIS posture summary and the three highest-value changes>
```

## Boundaries

- The scanner script executes with broad host visibility and can run as root. Confirmation is a workflow guardrail, not a sandbox.
- The official published Docker image is documented as outdated; cloudsec-pi does not pull or build it.
- A macOS run is blocked because Docker Desktop does not represent the underlying Linux host accurately.
- No remediation is applied.

## Avoid

- Supplying a script path through the prompt or tool arguments.
- Continuing after an identity-change failure.
- Calling the script through bash outside `cloudsec_docker_bench`.
- Reporting skipped checks as passes.
