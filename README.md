# cloudsec-pi

A defensive cloud and host security control plane for [Pi](https://pi.dev). It provides typed scanner tools, private evidence and workflow state, resumable serial audits, and a focused interactive control centre for Trivy, Docker Bench for Security, Lynis and Prowler CLI with Cloudflare.

## Safety first

Use cloudsec-pi only against targets you own or are expressly authorised to assess. The package is read-only: it does not remediate, exploit, connect through SSH or upload results.

Its confirmations are workflow guardrails, not a sandbox. Read [SECURITY.md](SECURITY.md) before privileged or credentialed scans.

## Requirements

- Pi 0.84 or newer.
- Node.js on macOS or Linux.
- Scanner CLIs installed explicitly by the operator. cloudsec-pi never installs or updates them.
- Docker Bench and Lynis host audits run only on the local Linux host.

## Install

From a local checkout:

```sh
pi install /absolute/path/to/cloudsec-pi
```

From GitHub:

```sh
pi install git:github.com/lacrimae0rerum/cloudsec-pi@main
```

Try without installing:

```sh
pi -e /absolute/path/to/cloudsec-pi
```

Pi packages execute with the user's full system permissions. Review the package and scanner source before installation.

## Scanner setup

Use official installation instructions:

- Trivy: https://trivy.dev/docs/latest/getting-started/installation/
- Docker Bench: https://github.com/docker/docker-bench-security#running-docker-bench-for-security
- Lynis: https://github.com/CISOfy/lynis#installation
- Prowler CLI: https://docs.prowler.com/getting-started/installation/prowler-cli

For Docker Bench, set an absolute path after reviewing the clone:

```sh
export DOCKER_BENCH_SECURITY_PATH=/absolute/path/to/docker-bench-security.sh
```

For Prowler Cloudflare, prefer a least-privilege API token through Prowler's native environment variable:

```sh
export CLOUDFLARE_API_TOKEN='<set outside shell history where possible>'
```

Do not pass secrets in prompts or tool arguments.

## Use

Open the interactive control centre:

```text
/cloudsec
```

Its focused commands are:

```text
/cloudsec-doctor [trivy|docker-bench|lynis|prowler]
/cloudsec-audit [audit-id]
/cloudsec-status [1..20]
/cloudsec-cancel [audit-id]
```

`/cloudsec-audit` selects scanners, records the authorised scope, executes them serially and preserves state between scanner attempts. Resuming with an audit id rebuilds every pending plan from the current project and environment. Privileged, credentialed and image-network plans receive a new five-minute TUI confirmation immediately before execution. Escape in the running loader aborts the scanner process group and waits for cancelled evidence to be written.

Ask Pi naturally:

```text
Audit this repository with Trivy.
Audit this local Linux Docker host against the CIS benchmark.
Run a privileged Lynis review of this local host.
Audit my authorised Cloudflare account with Prowler.
Plan the minimum cloud security audit for this project.
```

The matching skills are also available through Pi's skill command surface:

- `trivy-audit`
- `docker-bench-audit`
- `lynis-audit`
- `prowler-cloudflare-audit`
- `cloudsec-audit`

Run the doctor before a scan through `/cloudsec-doctor` or the `cloudsec_doctor` model tool. `cloudsec_status` exposes the same closed status projection as `/cloudsec-status`. The model-facing scanner tools remain available for focused single-scanner workflows.

## Evidence

Runs are stored privately under:

```text
${PI_CODING_AGENT_DIR:-~/.pi/agent}/cloudsec-pi/runs/
```

Directories use mode `0700`; files use `0600`. Native evidence remains local. Pi reads it through `cloudsec_evidence`, which confines paths, truncates output, strips Trivy secret payload fields and redacts common credential shapes. Evidence remains until you delete it.

Combined-audit state is stored separately under:

```text
${PI_CODING_AGENT_DIR:-~/.pi/agent}/cloudsec-pi/audits/
```

State contains closed scanner selections, lifecycle states and run identifiers only. It never stores plans, argv, executable paths, environment values or credentials. One exclusive `.workflow.lock` serialises combined audits. A lock left by a terminated Pi process fails closed and requires operator inspection; cloudsec-pi never kills a persisted PID or removes a stale lock automatically.

## Scope

v0.4 supports:

- Trivy filesystem scans inside the current project.
- Trivy image scans with network-aware confirmation.
- Docker Bench on the local Linux Docker host.
- Lynis on the local Linux host.
- Prowler CLI for Cloudflare.

The v0.4 control plane adds private status, serial combined-audit state, scanner-boundary resume, cancellation and the Pi TUI commands above. It does not add background scheduling, automatic retries, parallel scans or agentic evidence triage.

AWS, Azure, GCP, Kubernetes Prowler providers, remote execution, GitLab API posture and unattended CI remain outside v0.4.

## Verify a checkout

```sh
pi --no-extensions -e . --list-models
```

## Licence

MIT
