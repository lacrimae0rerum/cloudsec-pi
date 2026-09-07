---
name: cloudsec-setup
description: Guide optional local installation or configuration of missing cloudsec-pi scanners, explain setup prerequisites, or recover blocked setup. Use when scanner preparation rather than an audit is requested.
license: MIT
---

# Guided scanner setup

1. Direct the operator to `/cloudsec-setup` or **Setup** in `/cloudsec`. The human selects all/some scanners and approves each exact installation or configuration write in the TUI. This skill cannot grant approval or invoke an installer through a model tool or shell.
2. If setup is blocked, report the named missing manager, unsupported platform, failed probe or unsafe path. Use [README setup](../../README.md#scanner-setup) for supported official recipes and prerequisite links. Managers and privilege steps remain human-mediated; there is no automatic bootstrap or retry.
3. Keep credential values outside Pi. Explain only `CLOUDFLARE_API_TOKEN`, or `CLOUDFLARE_API_KEY` plus `CLOUDFLARE_API_EMAIL`, supplied through the operator's native environment or secret manager before Pi starts. Presence is not successful authentication.
4. Read the per-scanner outcome: reused, configured, installed-not-configured, unsupported, blocked, declined, cancelled, failed or pending. A declined config write leaves an installed scanner unregistered; it is not successful configuration. Partial install/source state requires local inspection before another explicit attempt.
5. Run `cloudsec_doctor` to verify availability after setup. Distinguish version/source identity, local daemon access, dependencies, privileges and unverified cloud authentication. An audit is a separate authorised workflow, never a setup validation step.

Doctor and scanner tools never install anything. Setup accepts no credentials, arbitrary package names, extra argv or install URLs. Docker Bench and Lynis remain local-Linux-only. Source hashes identify reviewed bytes, not upstream authenticity. Read [SECURITY.md](../../SECURITY.md) before approving installation code or a later audit.
