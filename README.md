# cloudsec-pi

A defensive cloud and host security control plane for [Pi](https://pi.dev). It provides typed scanner tools, private evidence and workflow state, resumable serial audits, and a focused interactive control centre for Trivy, Docker Bench for Security, Lynis and Prowler CLI with Cloudflare.

## Safety first

Use cloudsec-pi only against targets you own or are expressly authorised to assess. Audits are read-only: they do not remediate, exploit, connect through SSH or upload results. Optional scanner setup is a separate, explicitly confirmed local mutation.

Its confirmations are workflow guardrails, not a sandbox. Read [SECURITY.md](SECURITY.md) before privileged or credentialed scans.

## Requirements

- Pi 0.85.1 or newer.
- Node.js on macOS or Linux.
- Scanner CLIs installed by the operator or through the separately confirmed `/cloudsec-setup` workflow. Doctor and audits never install or upgrade scanners.
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

Run `/cloudsec-setup`, or choose **Setup** in `/cloudsec`. Select all scanners or choose some, then explicitly Continue. Escape cancels selection. Each missing scanner displays its official source, resolved installer executable, exact argv and filesystem/network effects before a fresh five-minute approval. Declining, timing out or cancelling stops with remaining scanners pending. There is no model-facing install tool.

Supported recipes reuse an **already installed** manager:

| Scanner | Guided recipe | Prerequisites and limitations |
|---|---|---|
| Trivy | `brew install homebrew/core/trivy` | Existing Homebrew on macOS/Linux |
| Prowler | `uv tool install --no-config --no-python-downloads --default-index https://pypi.org/simple prowler`, then `pipx install prowler --index-url https://pypi.org/simple`, otherwise `brew install homebrew/core/prowler` | Existing uv/pipx and compatible installed Python, or Homebrew; the manager resolves Python requirements |
| Lynis | `brew install homebrew/core/lynis` on Linux | Otherwise a structured human-terminal apt/dnf action, followed by an explicit one-shot re-probe; macOS unsupported by this harness |
| Docker Bench | `git -c core.hooksPath=/dev/null clone --depth 1 -- https://github.com/docker/docker-bench-security.git <private managed directory>` | Existing Git on Linux; no source overwrite, service start, container launch or host audit |

Missing managers produce a blocked result with official manual guidance. On Linux, installed apt/dnf can produce exact official Trivy repository/key steps or a Lynis install command for a separate human terminal. Pi never executes those privileged commands: choose **Re-probe once** after completing them, **Skip**, or cancel. A successful re-probe offers separately confirmed path persistence. Homebrew disk `brew.env` configuration is rejected rather than allowing it to inject alternate sources, credentials or wrappers. Setup never bootstraps managers, uses sudo, accepts a password, executes project-local installers, requests upgrades or forwards arbitrary arguments/URLs. Existing executables, including ones whose version probe fails, are never overwritten. Install output is withheld and bounded; a failed/cancelled install may leave package-manager or source state for manual inspection, never an automatic retry.

After installation, setup re-probes the executable and asks separately before saving its canonical absolute path to `${PI_CODING_AGENT_DIR:-~/.pi/agent}/cloudsec-pi/setup/config.json`. The versioned non-secret schema contains only `schemaVersion` and a closed `paths` map. Storage is private (`0700/0600`), atomic, bounded and canonical JSON; unsafe paths, symlinks, duplicate/unknown keys, traversal and permissive storage fail closed. No shell profile is edited. Doctor and audit plans reload this file on each call, including after a Pi restart. Explicit `CLOUDSEC_TRIVY_PATH`, `CLOUDSEC_LYNIS_PATH`, `CLOUDSEC_PROWLER_PATH` and `DOCKER_BENCH_SECURITY_PATH` environment entries take precedence. Stale saved paths affect only their selected scanner; explicit overrides and unrelated scanner use remain possible. Existing scanners can be adopted after a separately confirmed path write without installation. Malformed config requires local operator inspection.

A version probe confirms only executable availability. Docker Bench setup checks the fixed local socket with `docker --host unix:///var/run/docker.sock version --format '{{.Server.Version}}'`; daemon access, optional utilities and audit permissions remain distinct. It never starts Docker or contacts a remote context. The clone revision and script hash are displayed; a checksum proves integrity, not upstream provenance. Cloudflare credentials are reported by **name and presence only**, always authentication-unverified. Authentication and read-only audits require a separate confirmed workflow.

Official installation instructions:

- Trivy: https://trivy.dev/docs/latest/getting-started/installation/
- Docker Bench: https://github.com/docker/docker-bench-security#running-docker-bench-for-security
- Lynis: https://github.com/CISOfy/lynis#installation
- Prowler CLI: https://docs.prowler.com/getting-started/installation/prowler-cli

For Docker Bench, set an absolute path after reviewing the clone:

```sh
export DOCKER_BENCH_SECURITY_PATH=/absolute/path/to/docker-bench-security.sh
```

For Prowler Cloudflare, supply a least-privilege `CLOUDFLARE_API_TOKEN` through your native environment or secret manager before starting Pi. The alternative native pair is `CLOUDFLARE_API_KEY` and `CLOUDFLARE_API_EMAIL`. Follow https://docs.prowler.com/user-guide/providers/cloudflare/getting-started-cloudflare for permissions. Never put secret values in prompts, TUI inputs, tool arguments, logs or setup configuration.

## Use

Open the interactive control centre:

```text
/cloudsec
```

Its focused commands are:

```text
/cloudsec-setup
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
- `cloudsec-setup`

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

State contains closed scanner selections, lifecycle states and run identifiers only. It never stores plans, argv, executable paths, environment values or credentials. One exclusive `.workflow.lock` serialises combined audits. `setup/.tools.lock` additionally prevents concurrent setup mutations and scanner execution across Pi sessions. A lock left by a terminated Pi process fails closed and requires operator inspection; cloudsec-pi never kills a persisted PID or removes a stale lock automatically.

## Scope

v0.5 supports:

- Trivy filesystem scans inside the current project.
- Trivy image scans with network-aware confirmation.
- Docker Bench on the local Linux Docker host.
- Lynis on the local Linux host.
- Prowler CLI for Cloudflare.

The v0.5 control plane adds optional confirmed local setup to private status, serial combined-audit state, scanner-boundary resume, cancellation and the Pi TUI commands above. It does not add background scheduling, automatic retries, parallel scans or agentic evidence triage.

AWS, Azure, GCP, Kubernetes Prowler providers, remote execution, GitLab API posture and unattended CI remain outside v0.5.

## Verify a checkout

```sh
pi --offline --no-extensions -e .
```

Open `/cloudsec-setup` and press Escape, then `/cloudsec-doctor`. This exercises the extension factory and TUI without installing a scanner. `--list-models` alone is not a TUI/extension registration check. Live platform installs and cloud authentication are not covered by the package's deterministic fake-process validation.

## Licence

MIT
