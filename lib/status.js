import { existsSync, lstatSync, readdirSync, realpathSync } from "node:fs";
import { dirname } from "node:path";
import { getRunsRoot, readEvidence } from "./evidence.js";
import { SCANNER_IDS } from "./scanners.js";
import { listAuditStatuses } from "./audit-state.js";

const RUN_STATES = new Set(["running", "completed", "failed", "cancelled", "blocked", "declined"]);
const RISK_CLASSES = new Set(["local", "network-image", "script", "privileged-script", "privileged", "credentialed-network", "unknown"]);
const RUN_ID = /^[a-z0-9][a-z0-9._-]{0,127}$/i;

function validIso(value) {
  try {
    return value === undefined || (typeof value === "string" && new Date(value).toISOString() === value);
  } catch {
    return false;
  }
}

function scannerFromRunId(runId) {
  return [...SCANNER_IDS].sort((a, b) => b.length - a.length).find((scanner) => runId.startsWith(`${scanner}-`));
}

function projectMetadata(runId, metadata) {
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) throw new Error("Invalid run metadata");
  if (metadata.runId !== runId || !RUN_STATES.has(metadata.state)) throw new Error("Invalid run metadata");
  const scanner = metadata.scanner ?? metadata.plan?.scanner ?? scannerFromRunId(runId);
  const risk = metadata.risk ?? metadata.plan?.risk ?? "unknown";
  if (!SCANNER_IDS.includes(scanner) || !RISK_CLASSES.has(risk)) throw new Error("Invalid run metadata");
  if (!validIso(metadata.startedAt) || !validIso(metadata.endedAt)) throw new Error("Invalid run metadata");
  if (metadata.exitCode !== undefined && metadata.exitCode !== null && !Number.isInteger(metadata.exitCode)) {
    throw new Error("Invalid run metadata");
  }
  return {
    runId,
    scanner,
    state: metadata.state,
    startedAt: metadata.startedAt,
    endedAt: metadata.endedAt,
    exitCode: metadata.exitCode,
    risk,
  };
}

function normalizeLimit(value) {
  const limit = value ?? 10;
  if (!Number.isInteger(limit) || limit < 1 || limit > 20) throw new Error("Status limit must be an integer from 1 to 20");
  return limit;
}

export function collectRunStatus(options = {}) {
  const limit = normalizeLimit(options.limit);
  const root = getRunsRoot(options);
  if (!existsSync(root)) return { runs: [], invalidRuns: 0 };
  const rootStat = lstatSync(root);
  if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) throw new Error("Unsafe run root");
  const rootReal = realpathSync(root);
  const runs = [];
  let invalidRuns = 0;
  for (const entry of readdirSync(rootReal, { withFileTypes: true })) {
    try {
      if (!RUN_ID.test(entry.name) || entry.name.includes("..") || entry.isSymbolicLink() || !entry.isDirectory()) {
        throw new Error("Unsafe run directory");
      }
      const childReal = realpathSync(`${rootReal}/${entry.name}`);
      if (dirname(childReal) !== rootReal) throw new Error("Unsafe run directory");
      const evidence = readEvidence(entry.name, "metadata", { ...options, maxBytes: 20_000 });
      if (evidence.truncated) throw new Error("Run metadata is too large");
      runs.push(projectMetadata(entry.name, JSON.parse(evidence.text)));
    } catch {
      invalidRuns += 1;
    }
  }
  const time = (run) => Date.parse(run.startedAt ?? run.endedAt ?? "") || 0;
  runs.sort((a, b) => time(b) - time(a) || a.runId.localeCompare(b.runId));
  return { runs: runs.slice(0, limit), invalidRuns };
}

function display(value) {
  return value === undefined || value === null ? "-" : String(value);
}

export function formatRunStatus(status) {
  const lines = ["Recent scanner runs", "RUN | SCANNER | STATE | STARTED | ENDED | EXIT | RISK"];
  if (status.runs.length === 0) lines.push("(none)");
  for (const run of status.runs) {
    lines.push([
      run.runId,
      run.scanner,
      run.state,
      display(run.startedAt),
      display(run.endedAt),
      display(run.exitCode),
      run.risk,
    ].join(" | "));
  }
  if (status.invalidRuns > 0) lines.push(`Invalid run entries withheld: ${status.invalidRuns}`);
  return lines.join("\n");
}

export function collectCloudsecStatus(options = {}) {
  return { ...collectRunStatus(options), ...listAuditStatuses(options) };
}

export function formatCloudsecStatus(status) {
  const auditLines = ["Combined audits", "AUDIT | STATE | SCANNERS"];
  if (status.audits.length === 0) auditLines.push("(none)");
  for (const audit of status.audits) {
    auditLines.push(`${audit.auditId} | ${audit.state} | ${audit.scanners.map(({ scanner, state }) => `${scanner}:${state}`).join(", ")}`);
  }
  if (status.invalidAudits > 0) auditLines.push(`Invalid audit entries withheld: ${status.invalidAudits}`);
  return `${auditLines.join("\n")}\n\n${formatRunStatus(status)}`;
}
