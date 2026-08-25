import {
  chmodSync,
  closeSync,
  constants,
  existsSync,
  lstatSync,
  mkdtempSync,
  openSync,
  readdirSync,
  realpathSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { randomUUID } from "node:crypto";
import {
  DIR_MODE,
  FILE_MODE,
  ensurePrivateDir,
  getAgentDir,
  readPrivateFile,
  writePrivateJson,
} from "./evidence.js";

const AUDIT_ID = /^audit-[a-z0-9][a-z0-9._-]{0,127}$/i;
const RUN_ID = /^[a-z0-9][a-z0-9._-]{0,127}$/i;
const AUDIT_STATES = new Set(["pending", "running", "paused", "blocked", "failed", "cancelled", "completed"]);
const PHASE_STATES = new Set(["pending", "running", "completed", "failed", "cancelled"]);
const ATTEMPT_STATES = new Set(["running", "completed", "failed", "cancelled", "blocked", "declined"]);
const EVENTS = new Set([
  "audit_created",
  "audit_started",
  "phase_started",
  "phase_completed",
  "phase_failed",
  "phase_cancelled",
  "phase_blocked",
  "operator_paused",
  "operator_cancelled",
  "evidence_missing",
  "audit_completed",
]);
const ORDER = ["trivy", "docker-bench", "lynis", "prowler"];
const REQUEST_KEYS = { trivy: "trivy", "docker-bench": "dockerBench", lynis: "lynis", prowler: "prowler" };
const MAX_STATE_BYTES = 50_000;
const MAX_ATTEMPTS_PER_PHASE = 20;

function fail(message = "Invalid audit state") {
  throw new Error(message);
}

function plain(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function exactKeys(value, allowed, label) {
  if (!plain(value) || Object.keys(value).some((key) => !allowed.includes(key))) fail(`Invalid ${label}`);
}

function safeString(value, label, maximum) {
  if (typeof value !== "string" || value === "" || value.length > maximum || /[\0-\x1f\x7f]/.test(value) || value.startsWith("-")) {
    fail(`Invalid ${label}`);
  }
  return value;
}

function validIso(value) {
  try {
    return typeof value === "string" && new Date(value).toISOString() === value;
  } catch {
    return false;
  }
}

function requestKeys(request) {
  return ORDER.filter((scanner) => Object.hasOwn(request, REQUEST_KEYS[scanner]));
}

export function normalizeAuditRequest(raw) {
  exactKeys(raw, Object.values(REQUEST_KEYS), "audit request");
  const request = {};
  if (raw.trivy !== undefined) {
    exactKeys(raw.trivy, ["target", "path", "image"], "Trivy request");
    if (raw.trivy.target === "fs") {
      request.trivy = { target: "fs", path: safeString(raw.trivy.path ?? ".", "Trivy path", 4_096) };
    } else if (raw.trivy.target === "image") {
      const image = safeString(raw.trivy.image, "Trivy image", 512);
      if (!/^[A-Za-z0-9][A-Za-z0-9._/:@-]*$/.test(image)) fail("Invalid Trivy image");
      request.trivy = { target: "image", image };
    } else fail("Invalid Trivy target");
  }
  for (const key of ["dockerBench", "lynis"]) {
    if (raw[key] === undefined) continue;
    exactKeys(raw[key], ["privileged"], `${key} request`);
    if (raw[key].privileged !== undefined && typeof raw[key].privileged !== "boolean") fail(`Invalid ${key} privilege`);
    request[key] = { privileged: raw[key].privileged === true };
  }
  if (raw.prowler !== undefined) {
    exactKeys(raw.prowler, ["provider"], "Prowler request");
    if (raw.prowler.provider !== "cloudflare") fail("Invalid Prowler provider");
    request.prowler = { provider: "cloudflare" };
  }
  if (Object.keys(request).length === 0) fail("Audit request must select at least one scanner");
  return request;
}

function validateAttempt(attempt) {
  exactKeys(attempt, ["runId", "state", "startedAt", "endedAt", "exitCode", "exitSignal"], "audit attempt");
  if (!RUN_ID.test(attempt.runId) || !ATTEMPT_STATES.has(attempt.state)) fail();
  if (attempt.startedAt !== undefined && !validIso(attempt.startedAt)) fail();
  if (attempt.endedAt !== undefined && !validIso(attempt.endedAt)) fail();
  if (attempt.exitCode !== undefined && attempt.exitCode !== null && !Number.isInteger(attempt.exitCode)) fail();
  if (attempt.exitSignal !== undefined && attempt.exitSignal !== null && !/^SIG[A-Z0-9]+$/.test(attempt.exitSignal)) fail();
}

export function validateAuditDocument(value, expectedId) {
  if (Buffer.byteLength(JSON.stringify(value)) > MAX_STATE_BYTES) fail("Invalid audit state");
  exactKeys(value, ["schemaVersion", "auditId", "createdAt", "updatedAt", "state", "projectRoot", "request", "phases", "lastEvent"], "audit state");
  if (value.schemaVersion !== 1 || !AUDIT_ID.test(value.auditId) || value.auditId !== expectedId) fail();
  if (!validIso(value.createdAt) || !validIso(value.updatedAt) || !AUDIT_STATES.has(value.state)) fail();
  if (typeof value.projectRoot !== "string" || !isAbsolute(value.projectRoot) || /[\0\r\n]/.test(value.projectRoot)) fail();
  const request = normalizeAuditRequest(value.request);
  if (JSON.stringify(request) !== JSON.stringify(value.request)) fail();
  if (!Array.isArray(value.phases) || !EVENTS.has(value.lastEvent)) fail();
  const scanners = requestKeys(request);
  if (value.phases.length !== scanners.length) fail();
  value.phases.forEach((phase, index) => {
    exactKeys(phase, ["scanner", "state", "attempts"], "audit phase");
    if (phase.scanner !== scanners[index] || !PHASE_STATES.has(phase.state) || !Array.isArray(phase.attempts) || phase.attempts.length > MAX_ATTEMPTS_PER_PHASE) fail();
    phase.attempts.forEach(validateAttempt);
  });
  const running = value.phases.filter((phase) => phase.state === "running").length;
  if ((value.state === "running" && running !== 1) || (value.state !== "running" && running !== 0)) fail();
  if (value.state === "pending" && value.phases.some((phase) => phase.state !== "pending")) fail();
  if (value.state === "completed" && value.phases.some((phase) => phase.state !== "completed")) fail();
  if (value.state === "failed" && !value.phases.some((phase) => phase.state === "failed")) fail();
  return value;
}

export function getCloudsecRoot(options = {}) {
  return join(options.agentDir ?? getAgentDir(options.env), "cloudsec-pi");
}

export function getAuditsRoot(options = {}) {
  return join(getCloudsecRoot(options), "audits");
}

function validateAuditId(auditId) {
  if (!AUDIT_ID.test(auditId) || basename(auditId) !== auditId || auditId.includes("..")) fail("Invalid audit id");
}

function validateAuditDirectory(auditId, options) {
  validateAuditId(auditId);
  const root = getAuditsRoot(options);
  const rootStat = lstatSync(root);
  if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) fail("Unsafe audit root");
  const rootReal = realpathSync(root);
  const directory = resolve(rootReal, auditId);
  if (dirname(directory) !== rootReal) fail("Audit path escapes the private root");
  const stat = lstatSync(directory);
  if (stat.isSymbolicLink() || !stat.isDirectory()) fail("Unsafe audit directory");
  const real = realpathSync(directory);
  if (dirname(real) !== rootReal) fail("Audit path escapes the private root");
  return real;
}

function timestamp(now = Date.now) {
  return new Date(typeof now === "function" ? now() : now).toISOString();
}

export function createAuditDocument(draft, options = {}) {
  const request = normalizeAuditRequest(draft.request);
  const projectRoot = realpathSync(draft.projectRoot);
  const root = getAuditsRoot(options);
  ensurePrivateDir(getCloudsecRoot(options));
  ensurePrivateDir(root);
  const directory = mkdtempSync(join(root, "audit-"));
  chmodSync(directory, DIR_MODE);
  const auditId = basename(directory);
  const now = timestamp(options.now);
  const document = {
    schemaVersion: 1,
    auditId,
    createdAt: now,
    updatedAt: now,
    state: "pending",
    projectRoot,
    request,
    phases: requestKeys(request).map((scanner) => ({ scanner, state: "pending", attempts: [] })),
    lastEvent: "audit_created",
  };
  validateAuditDocument(document, auditId);
  writePrivateJson(directory, "state.json", document);
  return document;
}

export function readAuditDocument(auditId, options = {}) {
  const directory = validateAuditDirectory(auditId, options);
  const result = readPrivateFile(directory, "state.json", MAX_STATE_BYTES);
  if (result.truncated) fail("Invalid audit state");
  let value;
  try {
    value = JSON.parse(result.text);
  } catch {
    fail("Invalid audit state");
  }
  return validateAuditDocument(value, auditId);
}

export function writeAuditDocument(auditId, value, options = {}) {
  const directory = validateAuditDirectory(auditId, options);
  const next = { ...value, updatedAt: timestamp(options.now) };
  validateAuditDocument(next, auditId);
  writePrivateJson(directory, "state.json", next);
  return next;
}

export function listAuditStatuses(options = {}) {
  const root = getAuditsRoot(options);
  if (!existsSync(root)) return { audits: [], invalidAudits: 0 };
  const stat = lstatSync(root);
  if (stat.isSymbolicLink() || !stat.isDirectory()) fail("Unsafe audit root");
  const audits = [];
  let invalidAudits = 0;
  for (const entry of readdirSync(realpathSync(root), { withFileTypes: true })) {
    try {
      if (entry.isSymbolicLink() || !entry.isDirectory()) fail();
      const document = readAuditDocument(entry.name, options);
      audits.push({
        auditId: document.auditId,
        state: document.state,
        createdAt: document.createdAt,
        updatedAt: document.updatedAt,
        scanners: document.phases.map(({ scanner, state: phaseState }) => ({ scanner, state: phaseState })),
      });
    } catch {
      invalidAudits += 1;
    }
  }
  audits.sort((a, b) => Date.parse(b.updatedAt) - Date.parse(a.updatedAt) || a.auditId.localeCompare(b.auditId));
  const limit = options.limit ?? 10;
  if (!Number.isInteger(limit) || limit < 1 || limit > 20) fail("Status limit must be an integer from 1 to 20");
  return { audits: audits.slice(0, limit), invalidAudits };
}

export async function withWorkflowLock(auditId, options = {}, operation) {
  validateAuditId(auditId);
  const root = getCloudsecRoot(options);
  ensurePrivateDir(root);
  const path = join(root, ".workflow.lock");
  if (existsSync(path)) {
    const stat = lstatSync(path);
    if (stat.isSymbolicLink() || !stat.isFile()) fail("Unsafe workflow lock");
    fail("A cloudsec workflow is already active; stale locks require manual inspection");
  }
  let descriptor;
  const nonce = randomUUID();
  try {
    descriptor = openSync(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, FILE_MODE);
    writeFileSync(descriptor, `${JSON.stringify({ auditId, pid: process.pid, nonce, createdAt: timestamp(options.now) })}\n`);
    chmodSync(path, FILE_MODE);
    return await operation();
  } finally {
    if (descriptor !== undefined) {
      closeSync(descriptor);
      if (existsSync(path)) {
        const stat = lstatSync(path);
        if (!stat.isSymbolicLink() && stat.isFile()) {
          try {
            if (JSON.parse(readPrivateFile(root, ".workflow.lock", 1_024).text).nonce === nonce) unlinkSync(path);
          } catch {
            // Fail closed: never remove a lock whose ownership cannot be proven.
          }
        }
      }
    }
  }
}
