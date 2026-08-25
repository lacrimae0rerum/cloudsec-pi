import { accessSync, constants, lstatSync, realpathSync } from "node:fs";
import { execFile as execFileCallback } from "node:child_process";
import { delimiter, isAbsolute, join, resolve } from "node:path";
import { promisify } from "node:util";
import { SCANNERS, COMMON_ENV_NAMES, pickEnvironment } from "./scanners.js";

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
  const environment = options.env ?? process.env;
  if (!config.platforms.includes(platform)) {
    return { scanner, available: false, supported: false, reason: `Supported only on ${config.platforms.join(", ")}` };
  }

  if (scanner === "docker-bench") {
    const configured = environment.DOCKER_BENCH_SECURITY_PATH;
    if (!configured) return { scanner, available: false, supported: true, reason: "DOCKER_BENCH_SECURITY_PATH is not set" };
    try {
      const path = realpathSync(resolve(configured));
      const stat = lstatSync(path);
      return stat.isFile()
        ? { scanner, available: true, supported: true, path, version: "source script; version not probed" }
        : { scanner, available: false, supported: true, reason: "Configured path is not a regular file" };
    } catch (error) {
      return { scanner, available: false, supported: true, reason: error.message };
    }
  }

  const executable = (options.resolveExecutable ?? resolveExecutable)(config.command, environment);
  if (!executable) return { scanner, available: false, supported: true, reason: `${config.command} was not found on PATH` };
  try {
    const probe = options.probe ?? defaultProbe;
    const result = await probe(executable, config.versionArgs, {
      cwd: options.cwd ?? process.cwd(),
      env: pickEnvironment(COMMON_ENV_NAMES, environment),
    });
    const version = `${result.stdout ?? ""}\n${result.stderr ?? ""}`.trim().split("\n")[0] || "version output was empty";
    return { scanner, available: true, supported: true, path: executable, version };
  } catch (error) {
    return { scanner, available: true, supported: true, path: executable, reason: `Version probe failed: ${error.message}` };
  }
}

export async function inspectScanners(scanner, options = {}) {
  const ids = scanner ? [scanner] : Object.keys(SCANNERS);
  return Promise.all(ids.map((id) => inspectScanner(id, options)));
}

export function formatScannerStatuses(statuses) {
  return statuses.map((item) => `${item.scanner}: ${item.available ? "available" : "unavailable"}${item.path ? ` at ${item.path}` : ""}${item.version ? ` (${item.version})` : ""}${item.reason ? `; ${item.reason}` : ""}`).join("\n");
}
