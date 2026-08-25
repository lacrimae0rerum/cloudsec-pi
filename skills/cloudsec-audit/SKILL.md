---
name: cloudsec-audit
description: Plan and combine authorised cloud, container, IaC and local-host security audits using the minimum relevant cloudsec-pi scanner skills. Use for broad infrastructure security reviews or when the appropriate scanner is unclear.
license: MIT
---

# Cloud security audit

Choose the smallest scanner set that answers the user's question, then merge existing redacted evidence into one defensive report. For an operator-controlled multi-scanner run with private resume state, direct the user to `/cloudsec-audit`; do not imitate its persistence with ad hoc files.

## Selection

| Target or question | Skill |
|---|---|
| Repository, IaC, dependencies or secrets | `trivy-audit` with filesystem target |
| Container image | `trivy-audit` with image target |
| Local Linux Docker daemon and runtime | `docker-bench-audit` |
| Local Linux host posture | `lynis-audit` |
| Cloudflare account, zone, DNS or settings | `prowler-cloudflare-audit` |

Use more than one only when the scopes are genuinely distinct. A Docker host review may justify Docker Bench plus Lynis; an image review does not.

## Interactive combined workflow

- `/cloudsec` opens the control centre.
- `/cloudsec-audit` creates a new serial combined audit.
- `/cloudsec-audit <audit-id>` explicitly resumes failed, cancelled, blocked or incomplete work at a scanner boundary.
- `/cloudsec-status` lists the closed audit and run projection.
- Escape cancels the active scanner; `/cloudsec-cancel <audit-id>` cancels inactive workflow state.

Resume never reuses a plan or confirmation. Risky phases require a new immediate TUI confirmation.

## Procedure

1. Inventory the exact authorised targets. Split any target whose ownership or credentials differ.
2. Select the minimum skills from the table and state expected privilege, credentials and network access before execution.
3. Follow each selected skill. Never bypass its doctor, typed tool or confirmation branch.
4. Reuse completed run ids. Do not repeat a scan merely to obtain a different report layout.
5. Merge findings by affected asset and response. Preserve each scanner's native identifier and evidence run.
6. Return the report below. Keep native evidence local.

## Report

```markdown
# Cloud security audit

## Scope

| Target | Scanner | Run | Outcome |
|---|---|---|---|

## Prioritised findings

| Priority | Finding | Target | Scanner evidence | Minimum response |
|---|---|---|---|---|

## Coverage matrix

| Surface | Covered | Evidence | Gap |
|---|---|---|---|

## Trust and limitations

- Authorisation: <operator statement>
- Privilege used: <none or named runs>
- Credentials used: <variable names only>
- Expected egress: <scanner databases, registries or provider APIs>
- Residual gaps: <explicit>

## Verdict

<deployable, deployable with accepted risk, or not deployable, plus three priorities>
```

## Boundaries

- cloudsec-pi is read-only and interactive-first. It performs no remediation, SSH, CI automation or result upload.
- Tool confirmations are workflow guardrails, not scanner containment.
- A clean result is evidence for covered checks only, not proof of security.
- Combined audits are serial, have no automatic retry and resume only at scanner boundaries.
- kube-bench is the recommended next scanner for Kubernetes node CIS coverage; it is not included in v0.4.
