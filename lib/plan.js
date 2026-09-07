import { createHash } from "node:crypto";
import { chmodSync, lstatSync, mkdirSync, readFileSync, realpathSync } from "node:fs";
import { basename, dirname, isAbsolute, join, parse, relative, resolve, sep } from "node:path";
import { createRun, DIR_MODE, getAgentDir } from "./evidence.js";
import { resolveExecutable } from "./doctor.js";
import { CLOUDFLARE_ENV_NAMES, COMMON_ENV_NAMES, NETWORK_ENV_NAMES, pickEnvironment } from "./scanners.js";
import { assertSafePath, configuredEnvironment, PATH_NAMES } from "./setup-config.js";

function fail(message) {
  throw new Error(message);
}

function safeText(value, label, maximum = 512) {
  if (typeof value !== "string" || value === "") fail(`${label} is required`);
  if (value.startsWith("-")) fail(`${label} cannot start with '-'`);
  if (value.length > maximum || /[\0-\x1f\x7f]/.test(value)) fail(`${label} contains unsafe characters`);
  return value;
}

function resolveProjectTarget(raw, cwd) {
  safeText(raw, "Target path", 4_096);
  const project = realpathSync(cwd);
  const target = realpathSync(resolve(project, raw));
  const rel = relative(project, target);
  if (rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel)) fail("Target path must stay inside the current project");
  return target;
}

function validateImage(raw) {
  const image = safeText(raw, "Image reference");
  if (!/^[A-Za-z0-9][A-Za-z0-9._/:@-]*$/.test(image)) fail("Image reference contains unsupported characters");
  return image;
}

function environmentFor(scanner, source, additions = {}) {
  const names = [...COMMON_ENV_NAMES];
  if (scanner === "trivy" || scanner === "prowler") names.push(...NETWORK_ENV_NAMES);
  if (scanner === "prowler") names.push(...CLOUDFLARE_ENV_NAMES);
  return pickEnvironment(names, source, additions);
}

export function fileIdentity(path) {
  if (!isAbsolute(path)) fail("DOCKER_BENCH_SECURITY_PATH must be absolute");
  const resolved = resolve(path);
  if (basename(resolved) !== "docker-bench-security.sh") fail("Docker Bench path must end with docker-bench-security.sh");
  let current = resolved;
  while (true) {
    const stat = lstatSync(current);
    if (stat.isSymbolicLink()) fail(`Docker Bench path contains a symlink: ${current}`);
    if ((stat.mode & 0o022) !== 0) fail(`Docker Bench path is group/world writable: ${current}`);
    if (current === resolved && !stat.isFile()) fail("Docker Bench path is not a regular file");
    const parent = dirname(current);
    if (parent === current || current === parse(current).root) break;
    current = parent;
  }
  const stat = lstatSync(resolved);
  const currentUid = typeof process.getuid === "function" ? process.getuid() : stat.uid;
  if (stat.uid !== 0 && stat.uid !== currentUid) fail("Docker Bench script must be owned by the current user or root");
  return Object.freeze({
    path: resolved,
    size: stat.size,
    mtimeMs: stat.mtimeMs,
    sha256: createHash("sha256").update(readFileSync(resolved)).digest("hex"),
  });
}

export function verifyDockerBenchIdentity(identity) {
  const current = fileIdentity(identity.path);
  if (
    current.size !== identity.size ||
    current.mtimeMs !== identity.mtimeMs ||
    current.sha256 !== identity.sha256
  ) fail("Docker Bench script changed after confirmation");
  return true;
}

function freezePlan(plan) {
  Object.freeze(plan.args);
  Object.freeze(plan.env);
  Object.freeze(plan.envNames);
  Object.freeze(plan.risk);
  return Object.freeze(plan);
}

export function preparePlan(input, options = {}) {
  const cwd = options.cwd ?? process.cwd();
  const platform = options.platform ?? process.platform;
  const sourceEnv = configuredEnvironment(options);
  const agentDir = options.agentDir ?? getAgentDir(sourceEnv);
  const resolver = options.resolveExecutable ?? resolveExecutable;
  const runFactory = options.createRun ?? createRun;
  const scanner = input?.scanner;
  if (!["trivy", "docker-bench", "lynis", "prowler"].includes(scanner)) fail("Unknown scanner");
  if (["docker-bench", "lynis"].includes(scanner) && platform !== "linux") fail(`${scanner} audits are supported only on Linux`);

  if (scanner !== "docker-bench" && sourceEnv[PATH_NAMES[scanner]] !== undefined) assertSafePath(sourceEnv[PATH_NAMES[scanner]]);
  let executable;
  let args;
  let env;
  let risk = { requiresConfirmation: false, kind: "local", message: "Local unprivileged audit" };
  let acceptedExitCodes = [0];
  let identity;
  let preparedTarget;

  if (scanner === "trivy") {
    const trivy = resolver(sourceEnv[PATH_NAMES.trivy] ?? "trivy", sourceEnv);
    if (!trivy) fail("trivy was not found on PATH");
    const target = input.target;
    if (!['fs', 'image'].includes(target)) fail("Trivy target must be fs or image");
    preparedTarget = target === "fs" ? resolveProjectTarget(input.path, cwd) : validateImage(input.image);
    executable = trivy;
  } else if (scanner === "docker-bench") {
    const configured = sourceEnv.DOCKER_BENCH_SECURITY_PATH;
    if (!configured) fail("DOCKER_BENCH_SECURITY_PATH is not set");
    identity = fileIdentity(configured);
    const shell = resolver("sh", sourceEnv);
    if (!shell) fail("sh was not found on PATH");
    const privileged = input.privileged !== false;
    executable = privileged ? resolver("sudo", sourceEnv) : shell;
    if (!executable) fail(privileged ? "sudo was not found on PATH" : "sh was not found on PATH");
    preparedTarget = { shell, privileged };
    risk = {
      requiresConfirmation: true,
      kind: privileged ? "privileged-script" : "script",
      message: `Execute Docker Bench from ${identity.path} (SHA-256 ${identity.sha256})${privileged ? " with non-interactive sudo" : ""}`,
    };
  } else if (scanner === "lynis") {
    const lynis = resolver(sourceEnv[PATH_NAMES.lynis] ?? "lynis", sourceEnv);
    if (!lynis) fail("lynis was not found on PATH");
    const privileged = input.privileged === true;
    executable = privileged ? resolver("sudo", sourceEnv) : lynis;
    if (!executable) fail("sudo was not found on PATH");
    preparedTarget = { lynis, privileged };
    acceptedExitCodes = [0, 78];
    if (privileged) risk = { requiresConfirmation: true, kind: "privileged", message: "Run a local Linux host audit with non-interactive sudo" };
  } else {
    if (input.provider !== "cloudflare") fail("cloudsec-pi supports only Prowler Cloudflare audits");
    const prowler = resolver(sourceEnv[PATH_NAMES.prowler] ?? "prowler", sourceEnv);
    if (!prowler) fail("prowler was not found on PATH");
    const hasToken = Boolean(sourceEnv.CLOUDFLARE_API_TOKEN);
    const hasKeyPair = Boolean(sourceEnv.CLOUDFLARE_API_KEY && sourceEnv.CLOUDFLARE_API_EMAIL);
    if (!hasToken && !hasKeyPair) fail("Cloudflare credentials were not found in the native environment variables");
    executable = prowler;
    acceptedExitCodes = [0, 3];
    risk = { requiresConfirmation: true, kind: "credentialed-network", message: "Query authorised Cloudflare APIs with the listed environment variables" };
  }

  const run = runFactory(scanner, { agentDir, env: sourceEnv });
  if (scanner === "trivy") {
    const cacheDir = join(agentDir, "cloudsec-pi", "cache", "trivy");
    mkdirSync(cacheDir, { recursive: true, mode: DIR_MODE });
    chmodSync(cacheDir, DIR_MODE);
    args = [
      input.target,
      "--cache-dir",
      cacheDir,
      "--format",
      "json",
      "--output",
      join(run.dir, "trivy.json"),
      "--skip-version-check",
      "--disable-telemetry",
      ...(input.target === "fs" ? ["--scanners", "vuln,misconfig,secret", "--", preparedTarget] : ["--scanners", "vuln,secret", preparedTarget]),
    ];
    env = environmentFor(scanner, sourceEnv);
    if (input.target === "image") risk = { requiresConfirmation: true, kind: "network-image", message: "Scan a container image; registry or Docker socket access may occur" };
  } else if (scanner === "docker-bench") {
    args = preparedTarget.privileged
      ? ["-n", "--", preparedTarget.shell, identity.path, "-b"]
      : [identity.path, "-b"];
    env = environmentFor(scanner, sourceEnv);
  } else if (scanner === "lynis") {
    const scannerArgs = ["audit", "system", "--no-colors", "--report-file", join(run.dir, "lynis-report.dat")];
    args = preparedTarget.privileged ? ["-n", "--", preparedTarget.lynis, ...scannerArgs] : scannerArgs;
    env = environmentFor(scanner, sourceEnv);
  } else {
    args = ["cloudflare"];
    env = environmentFor(scanner, sourceEnv);
  }

  return freezePlan({
    scanner,
    toolLockOptions: Object.freeze({ agentDir }),
    executable,
    args,
    cwd: run.dir,
    runId: run.runId,
    runRoot: run.root,
    env,
    envNames: Object.keys(env).sort(),
    risk,
    acceptedExitCodes,
    identity,
  });
}

export function formatPlan(plan) {
  return [
    plan.risk.message,
    "",
    `Executable: ${plan.executable}`,
    `Arguments: ${JSON.stringify(plan.args)}`,
    `Working directory: ${plan.cwd}`,
    `Environment names: ${plan.envNames.join(", ") || "none"}`,
    `Evidence run: ${plan.runId}`,
  ].join("\n");
}
