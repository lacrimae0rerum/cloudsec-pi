# Security policy

## Operating boundary

cloudsec-pi is for defensive assessment of systems, artefacts and cloud resources that the operator owns or is expressly authorised to audit. It performs no remediation, exploitation, SSH or result upload.

The package validates and confirms the commands built by its own tools. It is not a sandbox. Installed scanners execute with the operator's rights, filesystem visibility, credentials and network access. TUI confirmations are workflow gates, not identity verification.

## Credential handling

- Tool schemas accept no secret values.
- Prowler reads Cloudflare credentials from its documented native environment variables.
- Scanner processes receive an allowlist of environment variables; metadata records names only.
- Native evidence is mode `0600` under a mode `0700` run directory.
- Model-visible evidence passes through traversal checks, truncation, structured Trivy secret-field removal and credential-shape redaction.
- Redaction is defence in depth, not a guarantee for every possible secret format; inspect native evidence locally and avoid sending complete reports to the model.

## Expected network access

| Scanner | Expected egress | Disabled or excluded |
|---|---|---|
| Trivy filesystem | Vulnerability database retrieval | Version check and telemetry flags |
| Trivy image | Vulnerability database, container registry or local Docker socket | Result uploads |
| Docker Bench | None during a host run | Image pulls and automatic source retrieval |
| Lynis | A DNS-based update check may occur in upstream defaults | Upload feature |
| Prowler Cloudflare | Authorised Cloudflare APIs | Prowler Cloud and hosted dashboards |

These are invocation policies, not network enforcement. Use an operating-system sandbox or firewall when containment is required.

## Docker Bench

`DOCKER_BENCH_SECURITY_PATH` must identify the official `docker-bench-security.sh` file on the local Linux host. cloudsec-pi rejects symlinks and writable path components, shows the SHA-256 during confirmation and rechecks identity before execution. The operator remains responsible for obtaining and reviewing the source.

## Combined-audit state

Combined audits are serial and resumable only at scanner boundaries. State lives under `${PI_CODING_AGENT_DIR:-~/.pi/agent}/cloudsec-pi/audits/` with directory mode `0700` and file mode `0600`. It stores closed public scanner selections, lifecycle state and run identifiers, never executable plans, environment values, credentials or evidence content.

Every resumed scanner is replanned against the current project and environment. Completed phases are skipped only while their evidence metadata still exists. Failed, cancelled, blocked and declined work requires an explicit resume and a new attempt. No scanner process is resumed and no attempt is retried automatically.

An exclusive private `.workflow.lock` permits one combined audit at a time. A process crash can leave a stale lock. cloudsec-pi deliberately does not reclaim it automatically or signal a persisted PID because PID reuse makes that unsafe. Inspect the private root and active Pi processes before removing a stale lock manually.

## Confirmation boundary

Privileged, credentialed and image-network plans accept confirmation only from Pi's interactive TUI. RPC, JSON and print modes fail closed even though RPC can implement dialog responses. Confirmations expire after five minutes and observe the same abort signal as execution. Previous confirmations and persisted state never authorise a resumed attempt.

## Evidence retention

Evidence and audit documents remain under the private cloudsec root until the operator removes them. The package performs no automatic destructive cleanup.

## Reporting vulnerabilities

Do not include credentials, cloud reports or customer data in a public issue. Report a minimal reproduction and affected version through the repository owner's private security channel when one is configured.
