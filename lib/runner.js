import { closeSync } from "node:fs";
import { spawn } from "node:child_process";
import { listNativeFiles, normalizeEvidencePermissions, openPrivateFile, writeMetadata } from "./evidence.js";
import { verifyDockerBenchIdentity } from "./plan.js";
import { withToolLock } from "./setup-config.js";

function iso(now) {
  return new Date(now()).toISOString();
}

export function recordPlanState(plan, state, options = {}) {
  const now = options.now ?? Date.now;
  writeMetadata(plan.cwd, {
    runId: plan.runId,
    scanner: plan.scanner,
    state,
    endedAt: iso(now),
    risk: plan.risk.kind,
  });
}

function killProcess(child, signal, kill = process.kill) {
  if (!child.pid) return;
  try {
    if (process.platform !== "win32") kill(-child.pid, signal);
    else child.kill(signal);
  } catch (error) {
    if (error?.code !== "ESRCH") throw error;
  }
}

function publicPlan(plan) {
  return {
    scanner: plan.scanner,
    executable: plan.executable,
    args: plan.args,
    cwd: plan.cwd,
    envNames: plan.envNames,
    risk: plan.risk.kind,
    identity: plan.identity,
  };
}

export async function runPlan(plan, options = {}) {
  if (plan.toolLockOptions) return withToolLock(plan.toolLockOptions, () => executePlan(plan, options));
  return executePlan(plan, options);
}

async function executePlan(plan, options) {
  const now = options.now ?? Date.now;
  const startedAt = iso(now);
  const base = {
    runId: plan.runId,
    scanner: plan.scanner,
    state: "running",
    startedAt,
    risk: plan.risk.kind,
    plan: publicPlan(plan),
  };
  writeMetadata(plan.cwd, base);

  if (options.signal?.aborted) {
    const metadata = { ...base, state: "cancelled", cancelledAt: iso(now), endedAt: iso(now) };
    writeMetadata(plan.cwd, metadata);
    return metadata;
  }

  try {
    if (plan.identity) verifyDockerBenchIdentity(plan.identity);
  } catch (error) {
    const metadata = { ...base, state: "failed", error: error.message, endedAt: iso(now) };
    writeMetadata(plan.cwd, metadata);
    throw error;
  }

  const stdout = openPrivateFile(plan.cwd, "stdout.log");
  const stderr = openPrivateFile(plan.cwd, "stderr.log");
  let child;
  try {
    child = (options.spawn ?? spawn)(plan.executable, plan.args, {
      cwd: plan.cwd,
      env: plan.env,
      detached: process.platform !== "win32",
      stdio: ["ignore", stdout.descriptor, stderr.descriptor],
    });
  } catch (error) {
    closeSync(stdout.descriptor);
    closeSync(stderr.descriptor);
    const metadata = { ...base, state: "failed", error: error.message, endedAt: iso(now) };
    writeMetadata(plan.cwd, metadata);
    throw error;
  }
  closeSync(stdout.descriptor);
  closeSync(stderr.descriptor);

  let cancelled = false;
  let killTimer;
  const abort = () => {
    if (cancelled) return;
    cancelled = true;
    killProcess(child, "SIGTERM", options.kill);
    killTimer = setTimeout(() => killProcess(child, "SIGKILL", options.kill), options.killGraceMs ?? 1_000);
    killTimer.unref?.();
  };
  options.signal?.addEventListener("abort", abort, { once: true });
  if (options.signal?.aborted) abort();

  const result = await new Promise((resolve) => {
    let spawnError;
    child.once("error", (error) => {
      spawnError = error;
    });
    child.once("close", (code, signal) => resolve({ code, signal, spawnError }));
  });

  if (killTimer) clearTimeout(killTimer);
  options.signal?.removeEventListener("abort", abort);
  let evidenceError;
  let reportFiles = [];
  try {
    normalizeEvidencePermissions(plan.cwd);
    reportFiles = listNativeFiles(plan.cwd);
  } catch (error) {
    evidenceError = error;
  }
  const accepted = result.code !== null && plan.acceptedExitCodes.includes(result.code);
  const state = cancelled ? "cancelled" : result.spawnError || evidenceError || !accepted ? "failed" : "completed";
  const metadata = {
    ...base,
    state,
    exitCode: result.code,
    exitSignal: result.signal,
    endedAt: iso(now),
    ...(cancelled ? { cancelledAt: iso(now) } : {}),
    ...(result.spawnError ? { error: result.spawnError.message } : evidenceError ? { error: `Evidence permission normalization failed: ${evidenceError.message}` } : {}),
    reportFiles,
  };
  writeMetadata(plan.cwd, metadata);
  return metadata;
}
