import {
  chmodSync,
  closeSync,
  constants,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readSync,
  readdirSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import { randomUUID } from "node:crypto";

export const DIR_MODE = 0o700;
export const FILE_MODE = 0o600;
const MAX_READ_BYTES = 50_000;
const NATIVE_EXTENSIONS = new Set([".csv", ".dat", ".json", ".jsonl", ".log", ".sarif", ".txt", ".xml"]);

export function getAgentDir(environment = process.env) {
  const configured = environment.PI_CODING_AGENT_DIR;
  if (!configured) return join(homedir(), ".pi", "agent");
  return resolve(configured.replace(/^~(?=\/|$)/, homedir()));
}

export function getRunsRoot(options = {}) {
  const agentDir = options.agentDir ?? getAgentDir(options.env);
  return join(agentDir, "cloudsec-pi", "runs");
}

export function ensurePrivateDir(path) {
  mkdirSync(path, { recursive: true, mode: DIR_MODE });
  const stat = lstatSync(path);
  if (stat.isSymbolicLink() || !stat.isDirectory()) throw new Error(`Unsafe evidence directory: ${path}`);
  chmodSync(path, DIR_MODE);
}

export function createRun(scanner, options = {}) {
  const root = getRunsRoot(options);
  ensurePrivateDir(dirname(root));
  ensurePrivateDir(root);
  const dir = mkdtempSync(join(root, `${scanner}-`));
  chmodSync(dir, DIR_MODE);
  return Object.freeze({ runId: basename(dir), dir, root });
}

function assertFileName(name) {
  if (!name || basename(name) !== name || name.includes("\0") || name === "." || name === "..") {
    throw new Error("Invalid evidence file name");
  }
}

export function openPrivateFile(runDir, name) {
  assertFileName(name);
  const path = join(runDir, name);
  const descriptor = openSync(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, FILE_MODE);
  chmodSync(path, FILE_MODE);
  return { descriptor, path };
}

export function writePrivateJson(directory, name, value) {
  assertFileName(name);
  const finalPath = join(directory, name);
  const tempPath = join(directory, `.${name}-${randomUUID()}.tmp`);
  try {
    writeFileSync(tempPath, `${JSON.stringify(value, null, 2)}\n`, { flag: "wx", mode: FILE_MODE });
    chmodSync(tempPath, FILE_MODE);
    renameSync(tempPath, finalPath);
    chmodSync(finalPath, FILE_MODE);
  } finally {
    if (existsSync(tempPath)) unlinkSync(tempPath);
  }
}

export function writeMetadata(runDir, metadata) {
  writePrivateJson(runDir, "metadata.json", metadata);
}

export function normalizeEvidencePermissions(runDir) {
  chmodSync(runDir, DIR_MODE);
  let visited = 0;
  const walk = (directory, depth) => {
    // ponytail: bounded traversal; deeper scanner output remains protected by its 0700 ancestors.
    if (depth > 5 || visited >= 10_000) return;
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (visited++ >= 10_000) return;
      const path = join(directory, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        chmodSync(path, DIR_MODE);
        walk(path, depth + 1);
      } else if (entry.isFile()) chmodSync(path, FILE_MODE);
    }
  };
  walk(runDir, 0);
}

export function listNativeFiles(runDir) {
  const files = [];
  const walk = (dir, prefix, depth) => {
    if (depth > 3) return;
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.isSymbolicLink()) continue;
      const relativePath = prefix ? join(prefix, entry.name) : entry.name;
      const fullPath = join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(fullPath, relativePath, depth + 1);
        continue;
      }
      if (!entry.isFile() || ["metadata.json", "stdout.log", "stderr.log"].includes(relativePath)) continue;
      const extension = entry.name.includes(".") ? `.${entry.name.split(".").pop().toLowerCase()}` : "";
      if (NATIVE_EXTENSIONS.has(extension)) files.push(relativePath);
    }
  };
  walk(runDir, "", 0);
  return files.sort();
}

function validateRunDir(root, runId) {
  if (!/^[a-z0-9][a-z0-9._-]{0,127}$/i.test(runId) || runId.includes("..") || basename(runId) !== runId) {
    throw new Error("Invalid run id");
  }
  const rootReal = realpathSync(root);
  const candidate = resolve(rootReal, runId);
  if (dirname(candidate) !== rootReal) throw new Error("Evidence path escapes the run root");
  const stat = lstatSync(candidate);
  if (stat.isSymbolicLink() || !stat.isDirectory()) throw new Error("Unsafe run directory");
  const candidateReal = realpathSync(candidate);
  if (dirname(candidateReal) !== rootReal) throw new Error("Evidence path escapes the run root");
  return candidateReal;
}

function safeRead(path, maxBytes) {
  const stat = lstatSync(path);
  if (stat.isSymbolicLink() || !stat.isFile()) throw new Error("Unsafe evidence file");
  const descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const buffer = Buffer.alloc(maxBytes + 1);
    const bytesRead = readSync(descriptor, buffer, 0, buffer.length, 0);
    return {
      text: new TextDecoder().decode(buffer.subarray(0, Math.min(bytesRead, maxBytes))),
      truncated: bytesRead > maxBytes,
    };
  } finally {
    closeSync(descriptor);
  }
}

export function readPrivateFile(directory, name, maxBytes = MAX_READ_BYTES) {
  assertFileName(name);
  try {
    return safeRead(join(directory, name), Math.max(1, Math.min(maxBytes, MAX_READ_BYTES)));
  } catch (error) {
    if (error.message === "Unsafe evidence file") throw new Error("Unsafe private file");
    throw error;
  }
}

export function redactEvidence(text) {
  return text
    .replace(/-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----[\s\S]*?-----END(?: [A-Z0-9]+)* PRIVATE KEY-----/g, "[REDACTED PRIVATE KEY]")
    .replace(/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, "[REDACTED AWS KEY]")
    .replace(/\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b/g, "[REDACTED GITHUB TOKEN]")
    .replace(/\bsk-[A-Za-z0-9_-]{20,}\b/g, "[REDACTED API TOKEN]")
    .replace(/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, "[REDACTED SLACK TOKEN]")
    .replace(/\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g, "[REDACTED JWT]")
    .replace(/\bBearer\s+[A-Za-z0-9._~+\/-]+=*/gi, "Bearer [REDACTED]")
    .replace(/((?:api[_-]?key|authorization|client[_-]?secret|password|private[_-]?key|secret|token)["']?\s*[:=]\s*")([^"]*)(")/gi, "$1[REDACTED]$3")
    .replace(/((?:api[_-]?key|authorization|client[_-]?secret|password|private[_-]?key|secret|token)["']?\s*[:=]\s*')([^']*)(')/gi, "$1[REDACTED]$3")
    .replace(
      /((?:api[_-]?key|authorization|client[_-]?secret|password|private[_-]?key|secret|token)["']?\s*[:=]\s*)([^\s,"'\\}]+)/gi,
      "$1[REDACTED]",
    );
}

function redactStructuredReport(file, text) {
  const redactFields = (value, key = "") => {
    if (["code", "content", "match", "raw"].includes(key.toLowerCase())) return "[REDACTED]";
    if (Array.isArray(value)) return value.map((item) => redactFields(item));
    if (value && typeof value === "object") {
      return Object.fromEntries(Object.entries(value).map(([name, item]) => [name, redactFields(item, name)]));
    }
    return value;
  };
  const lower = file.toLowerCase();
  try {
    if (lower.endsWith(".json")) return JSON.stringify(redactFields(JSON.parse(text)), null, 2);
    if (lower.endsWith(".jsonl")) {
      return text.split("\n").map((line) => line ? JSON.stringify(redactFields(JSON.parse(line))) : "").join("\n");
    }
  } catch {
    if (lower.endsWith(".json") || lower.endsWith(".jsonl")) return "[Malformed structured report withheld]";
  }
  return text;
}

function readNativeReports(runDir, maxBytes) {
  const files = listNativeFiles(runDir);
  if (files.length === 0) return { text: "No native report files were found.", truncated: false };
  let remaining = maxBytes;
  let text = "";
  let truncated = false;
  for (const file of files) {
    if (remaining <= 0) {
      truncated = true;
      break;
    }
    const fullPath = resolve(runDir, file);
    const rel = relative(runDir, fullPath);
    if (rel.startsWith(`..${sep}`) || rel === ".." || resolve(runDir, rel) !== fullPath) throw new Error("Unsafe report path");
    const section = safeRead(fullPath, remaining);
    const header = `${text ? "\n\n" : ""}## ${file}\n`;
    text += header + redactStructuredReport(file, section.text);
    remaining = maxBytes - Buffer.byteLength(text);
    truncated ||= section.truncated;
  }
  return { text, truncated };
}

export function readEvidence(runId, file, options = {}) {
  const maxBytes = Math.max(1_024, Math.min(Number(options.maxBytes ?? 20_000), MAX_READ_BYTES));
  const root = getRunsRoot(options);
  const runDir = validateRunDir(root, runId);
  let result;
  if (file === "report") result = readNativeReports(runDir, maxBytes);
  else {
    const names = { metadata: "metadata.json", stdout: "stdout.log", stderr: "stderr.log" };
    const name = names[file];
    if (!name) throw new Error("Unknown evidence file class");
    result = safeRead(join(runDir, name), maxBytes);
  }
  const redacted = redactEvidence(result.text);
  const bytes = Buffer.from(redacted);
  const truncated = result.truncated || bytes.length > maxBytes;
  const notice = `\n\n[Evidence truncated to ${maxBytes} bytes.]`;
  const contentLimit = truncated ? Math.max(0, maxBytes - Buffer.byteLength(notice)) : maxBytes;
  const text = bytes.length > contentLimit ? new TextDecoder().decode(bytes.subarray(0, contentLimit)) : redacted;
  return { text: truncated ? text + notice : text, truncated, maxBytes };
}
