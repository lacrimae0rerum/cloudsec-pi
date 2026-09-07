import { accessSync, constants, lstatSync, realpathSync } from "node:fs";
import { execFile as execFileCallback } from "node:child_process";
import { delimiter, isAbsolute, join, resolve } from "node:path";
import { promisify } from "node:util";
import { SCANNERS, COMMON_ENV_NAMES, pickEnvironment } from "./scanners.js";
import { assertSafePath, configuredEnvironment, PATH_NAMES } from "./setup-config.js";
import { redactEvidence } from "./evidence.js";

const execFile = promisify(execFileCallback);

export function resolveExecutable(command, environment = process.env) {
  const candidates = isAbsolute(command)
    ? [command]
    : (environment.PATH ?? "")
        .split(delimiter)
        .filter(Boolean)
        .map((directory) => join(directory, command));
  for (const candidate of candidates) {
    try {
      accessSync(candidate, constants.X_OK);
      return realpathSync(candidate);
    } catch {
      // Continue through PATH.
    }
  }
  return undefined;
}

async function defaultProbe(executable, args, options) {
  return execFile(executable, args, {
    cwd: options.cwd,
    env: options.env,
    timeout: 5_000,
    maxBuffer: 64 * 1024,
  });
}

export async function inspectScanner(scanner, options = {}) {
  const config = SCANNERS[scanner];
  if (!config) throw new Error(`Unknown scanner: ${scanner}`);
  const platform = options.platform ?? process.platform;
  const environment = configuredEnvironment(options);
  if (!config.platforms.includes(platform)) {
    return { scanner, available: false, supported: false, reason: `Supported only on ${config.platforms.join(", ")}` };
  }

  if (scanner === "docker-bench") {
    const configured = environment.DOCKER_BENCH_SECURITY_PATH;
    if (!configured) return { scanner, available: false, supported: true, reason: "DOCKER_BENCH_SECURITY_PATH is not set" };
    try {
      const { fileIdentity } = await import("./plan.js");
      const identity = fileIdentity(configured);
      return { scanner, available: true, supported: true, path: identity.path, version: `source script; SHA-256 ${identity.sha256}; audit dependencies and permissions unverified` };
    } catch (error) {
      return { scanner, available: false, supported: true, path: configured, reason: "Unsafe or unavailable configured Docker Bench source" };
    }
  }

  if (Object.hasOwn(environment, PATH_NAMES[scanner])) {
    try { assertSafePath(environment[PATH_NAMES[scanner]]); }
    catch { return { scanner, available: false, supported: true, path: environment[PATH_NAMES[scanner]], reason: "Configured executable is missing or unsafe; readiness unverified" }; }
  }
  const executable = (options.resolveExecutable ?? resolveExecutable)(environment[PATH_NAMES[scanner]] ?? config.command, environment);
  if (!executable) return { scanner, available: false, supported: true, reason: `${config.command} was not found on PATH` };
  try {
    const probe = options.probe ?? defaultProbe;
    const result = await probe(executable, config.versionArgs, {
      cwd: options.cwd ?? process.cwd(),
      env: pickEnvironment(COMMON_ENV_NAMES, environment),
    });
    const version = redactEvidence(`${result.stdout ?? ""}\n${result.stderr ?? ""}`).replace(/[\x00-\x08\x0b-\x1f\x7f]/g, "").trim().split("\n")[0]?.slice(0, 512);
    if (!version) throw new Error("Empty version output");
    return { scanner, available: true, supported: true, path: executable, version };
  } catch (error) {
    return { scanner, available: false, supported: true, path: executable, reason: "Version probe failed or returned empty output; readiness unverified" };
  }
}

export async function inspectScanners(scanner, options = {}) {
  const ids = scanner ? [scanner] : Object.keys(SCANNERS);
  return Promise.all(ids.map((id) => inspectScanner(id, options)));
}

export function formatScannerStatuses(statuses) {
  return statuses.map((item) => `${item.scanner}: ${item.available ? "available" : "unavailable"}${item.path ? ` at ${item.path}` : ""}${item.version ? ` (${item.version})` : ""}${item.reason ? `; ${item.reason}` : ""}`).join("\n");
}
