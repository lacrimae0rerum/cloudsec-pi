import { constants, closeSync, fstatSync, lstatSync, mkdirSync, openSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { getAgentDir, writePrivateJson } from "./evidence.js";
import { SCANNER_IDS } from "./scanners.js";

export const PATH_NAMES = Object.freeze({ trivy: "CLOUDSEC_TRIVY_PATH", lynis: "CLOUDSEC_LYNIS_PATH", prowler: "CLOUDSEC_PROWLER_PATH", "docker-bench": "DOCKER_BENCH_SECURITY_PATH" });
export function setupRoot(options = {}) { return join(options.agentDir ?? getAgentDir(options.env), "cloudsec-pi", "setup"); }

export function assertSafePath(path, { missing = false, privateLeaf = false } = {}) {
  if (typeof path !== "string" || !isAbsolute(path) || path !== resolve(path) || path.length > 4096 || /[\x00-\x1f\x7f]/.test(path)) throw new Error("Unsafe setup path");
  let current = path;
  while (true) {
    try {
      const stat = lstatSync(current);
      if (stat.isSymbolicLink() || (stat.mode & 0o022) || (!stat.isDirectory() && current !== path)) throw new Error("Unsafe setup path permissions or symlink");
      if (privateLeaf && current === path && ((stat.mode & 0o777) !== (stat.isDirectory() ? 0o700 : 0o600) || stat.uid !== process.getuid?.())) throw new Error("Setup storage must be private and user-owned");
    } catch (error) { if (!(missing && error.code === "ENOENT")) throw error; }
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return path;
}

export function ensureSetupDir(path) {
  assertSafePath(path, { missing: true });
  try { lstatSync(path); } catch (error) {
    if (error.code !== "ENOENT") throw error;
    try { lstatSync(dirname(path)); } catch (parentError) {
      if (parentError.code !== "ENOENT") throw parentError;
      ensureSetupDir(dirname(path));
    }
    mkdirSync(path, { mode: 0o700 });
  }
  assertSafePath(path, { privateLeaf: true });
}

function validateConfig(value) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype || Object.keys(value).some((key) => !["schemaVersion", "paths"].includes(key)) || value.schemaVersion !== 1 || !value.paths || Object.getPrototypeOf(value.paths) !== Object.prototype) throw new Error("Invalid setup configuration");
  for (const [scanner, path] of Object.entries(value.paths)) {
    if (!SCANNER_IDS.includes(scanner)) throw new Error("Unknown setup configuration key");
    if (typeof path !== "string" || !isAbsolute(path) || path !== resolve(path) || path.length > 4096 || /[\x00-\x1f\x7f]/.test(path)) throw new Error("Unsafe setup path");
  }
  return value;
}

export function readSetupConfig(options = {}) {
  const root = setupRoot(options);
  try { lstatSync(root); } catch (error) {
    if (error.code === "ENOENT") return { schemaVersion: 1, paths: {} };
    throw error;
  }
  assertSafePath(root);
  const path = join(root, "config.json");
  assertSafePath(root, { privateLeaf: true });
  try { lstatSync(path); } catch (error) {
    if (error.code === "ENOENT") return { schemaVersion: 1, paths: {} };
    throw error;
  }
  assertSafePath(path, { privateLeaf: true });
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    if (fstatSync(fd).size > 20_000) throw new Error("Setup configuration too large");
    const text = readFileSync(fd, "utf8");
    const value = JSON.parse(text);
    if (text !== `${JSON.stringify(value, null, 2)}\n`) throw new Error("Non-canonical setup configuration");
    return validateConfig(value);
  } finally { closeSync(fd); }
}

export function writeSetupConfig(value, options = {}) {
  validateConfig(value);
  for (const path of Object.values(value.paths)) assertSafePath(path, { missing: true });
  const root = setupRoot(options);
  ensureSetupDir(root);
  readSetupConfig(options);
  writePrivateJson(root, "config.json", value);
}

export function configuredEnvironment(options = {}) {
  const env = options.env ?? process.env;
  const config = readSetupConfig(options);
  const merged = { ...env };
  for (const [scanner, path] of Object.entries(config.paths)) {
    if (!Object.hasOwn(env, PATH_NAMES[scanner])) merged[PATH_NAMES[scanner]] = path;
  }
  return merged;
}

// ponytail: one global execution lock; per-tool locks only if parallel scans become a requirement.
export async function withToolLock(options, operation) {
  const root = setupRoot(options);
  ensureSetupDir(root);
  const path = join(root, ".tools.lock");
  let fd;
  try { fd = openSync(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600); }
  catch { throw new Error("Scanner/setup execution locked; inspect active processes before manually removing a stale lock"); }
  const identity = fstatSync(fd);
  writeFileSync(fd, `${process.pid}\n`);
  try { return await operation(); }
  finally {
    closeSync(fd);
    try {
      const current = lstatSync(path);
      if (!current.isSymbolicLink() && current.ino === identity.ino && current.dev === identity.dev) unlinkSync(path);
    } catch (error) { if (error.code !== "ENOENT") throw error; }
  }
}
