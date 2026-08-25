import { realpathSync } from "node:fs";
import {
  createAuditDocument,
  listAuditStatuses,
  normalizeAuditRequest,
  readAuditDocument,
  withWorkflowLock,
  writeAuditDocument,
} from "./audit-state.js";
import { readEvidence } from "./evidence.js";
import { formatPlan, preparePlan } from "./plan.js";
import { recordPlanState, runPlan } from "./runner.js";

const CONFIRM_TIMEOUT_MS = 300_000;
const MAX_ATTEMPTS_PER_PHASE = 20;
const REQUEST_KEY = { trivy: "trivy", "docker-bench": "dockerBench", lynis: "lynis", prowler: "prowler" };

function stateOptions(context) {
  return { agentDir: context.agentDir, env: context.env, now: context.now };
}

function inputFor(document, scanner) {
  return { scanner, ...document.request[REQUEST_KEY[scanner]] };
}

function publicStatus(document, message) {
  return {
    auditId: document.auditId,
    state: document.state,
    createdAt: document.createdAt,
    updatedAt: document.updatedAt,
    scanners: document.phases.map((phase) => ({
      scanner: phase.scanner,
      state: phase.state,
      attempts: phase.attempts.map(({ runId, state }) => ({ runId, state })),
    })),
    ...(message ? { message } : {}),
  };
}

function timestamp(now = Date.now) {
  return new Date(typeof now === "function" ? now() : now).toISOString();
}

function attemptFrom(metadata) {
  return {
    runId: metadata.runId,
    state: metadata.state,
    startedAt: metadata.startedAt,
    endedAt: metadata.endedAt,
    exitCode: metadata.exitCode,
    exitSignal: metadata.exitSignal,
  };
}

function defaultReadRunOutcome(runId, context) {
  try {
    const result = readEvidence(runId, "metadata", { ...stateOptions(context), maxBytes: 20_000 });
    if (result.truncated) return undefined;
    const metadata = JSON.parse(result.text);
    if (metadata.runId !== runId || !["running", "completed", "failed", "cancelled"].includes(metadata.state)) return undefined;
    return {
      runId,
      state: metadata.state,
      startedAt: metadata.startedAt,
      endedAt: metadata.endedAt,
      exitCode: metadata.exitCode,
      exitSignal: metadata.exitSignal,
    };
  } catch {
    return undefined;
  }
}

function defaultEvidenceExists(runId, context) {
  return defaultReadRunOutcome(runId, context)?.state === "completed";
}

function linkSignal(source, controller) {
  if (!source) return () => {};
  const abort = () => controller.abort();
  if (source.aborted) abort();
  else source.addEventListener("abort", abort, { once: true });
  return () => source.removeEventListener("abort", abort);
}

export function createOrchestrator(overrides = {}) {
  const dependencies = {
    createAuditDocument,
    evidenceExists: defaultEvidenceExists,
    formatPlan,
    listAuditStatuses,
    preparePlan,
    readAuditDocument,
    readRunOutcome: defaultReadRunOutcome,
    recordPlanState,
    runPlan,
    withWorkflowLock,
    writeAuditDocument,
    ...overrides,
  };
  const active = new Map();

  function startAudit(request, context = {}) {
    const normalized = normalizeAuditRequest(request);
    const projectRoot = realpathSync(context.cwd ?? process.cwd());
    const document = dependencies.createAuditDocument({ projectRoot, request: normalized }, stateOptions(context));
    return publicStatus(document);
  }

  function getAuditStatus(auditId, context = {}) {
    return publicStatus(dependencies.readAuditDocument(auditId, stateOptions(context)));
  }

  function listAudits(context = {}) {
    return dependencies.listAuditStatuses({ ...stateOptions(context), limit: context.limit });
  }

  async function resumeAudit(auditId, context = {}) {
    return dependencies.withWorkflowLock(auditId, stateOptions(context), async () => {
      let document = dependencies.readAuditDocument(auditId, stateOptions(context));
      const currentProject = realpathSync(context.cwd ?? process.cwd());
      if (currentProject !== document.projectRoot) throw new Error("Combined audits must resume from their original project");

      const controller = new AbortController();
      const unlinkSignal = linkSignal(context.signal, controller);
      active.set(auditId, controller);
      const save = (next) => {
        document = dependencies.writeAuditDocument(auditId, next, stateOptions(context));
        return document;
      };

      try {
        let reconciled = false;
        for (const phase of document.phases) {
          const attempt = phase.attempts.at(-1);
          if (phase.state !== "running" || attempt?.state !== "running") continue;
          const outcome = dependencies.readRunOutcome(attempt.runId, context);
          if (!outcome || outcome.state === "running") continue;
          Object.assign(attempt, attemptFrom(outcome));
          phase.state = outcome.state;
          document.state = outcome.state === "completed" ? "paused" : outcome.state;
          document.lastEvent = outcome.state === "completed" ? "phase_completed" : outcome.state === "cancelled" ? "phase_cancelled" : "phase_failed";
          reconciled = true;
        }
        if (reconciled) {
          if (document.phases.every((phase) => phase.state === "completed")) {
            document.state = "completed";
            document.lastEvent = "audit_completed";
          }
          save(document);
        }

        for (const phase of document.phases) {
          if (phase.state !== "completed") continue;
          const attempt = phase.attempts.at(-1);
          if (!attempt || !dependencies.evidenceExists(attempt.runId, context)) {
            phase.state = "pending";
            document.state = "paused";
            document.lastEvent = "evidence_missing";
          }
        }
        if (document.lastEvent === "evidence_missing") save(document);
        if (document.state === "completed" && document.phases.every((phase) => phase.state === "completed")) {
          return publicStatus(document);
        }

        for (const phase of document.phases) {
          if (["failed", "cancelled", "running"].includes(phase.state)) phase.state = "pending";
        }

        for (const phase of document.phases) {
          if (phase.state === "completed") continue;
          if (controller.signal.aborted) {
            phase.state = "cancelled";
            document.state = "cancelled";
            document.lastEvent = "phase_cancelled";
            return publicStatus(save(document));
          }

          // ponytail: bounded history avoids an unbounded state file; start a new audit after 20 attempts.
          if (phase.attempts.length >= MAX_ATTEMPTS_PER_PHASE) {
            document.state = "blocked";
            document.lastEvent = "phase_blocked";
            return publicStatus(save(document), "This scanner reached the 20-attempt audit history limit; start a new combined audit");
          }

          let plan;
          try {
            plan = dependencies.preparePlan(inputFor(document, phase.scanner), {
              cwd: currentProject,
              agentDir: context.agentDir,
              env: context.env,
              platform: context.platform,
              resolveExecutable: context.resolveExecutable,
              createRun: context.createRun,
            });
          } catch (error) {
            document.state = "blocked";
            document.lastEvent = "phase_blocked";
            return publicStatus(save(document), error.message);
          }

          if (plan.risk.requiresConfirmation) {
            if (context.mode !== "tui" || typeof context.confirm !== "function") {
              dependencies.recordPlanState(plan, "blocked", { now: context.now });
              phase.attempts.push({ runId: plan.runId, state: "blocked", endedAt: timestamp(context.now) });
              document.state = "blocked";
              document.lastEvent = "phase_blocked";
              return publicStatus(save(document), "This scanner requires TUI confirmation");
            }
            const confirmed = await context.confirm(
              "Confirm cloud security audit",
              dependencies.formatPlan(plan),
              { timeout: CONFIRM_TIMEOUT_MS, signal: controller.signal },
            );
            if (!confirmed) {
              const cancelled = controller.signal.aborted;
              dependencies.recordPlanState(plan, cancelled ? "cancelled" : "declined", { now: context.now });
              phase.attempts.push({ runId: plan.runId, state: cancelled ? "cancelled" : "declined", endedAt: timestamp(context.now) });
              phase.state = cancelled ? "cancelled" : "pending";
              document.state = cancelled ? "cancelled" : "paused";
              document.lastEvent = cancelled ? "phase_cancelled" : "operator_paused";
              return publicStatus(save(document));
            }
          }

          phase.state = "running";
          const attempt = { runId: plan.runId, state: "running", startedAt: timestamp(context.now) };
          phase.attempts.push(attempt);
          document.state = "running";
          document.lastEvent = "phase_started";
          save(document);

          let metadata;
          try {
            metadata = await dependencies.runPlan(plan, { signal: controller.signal });
          } catch (error) {
            attempt.state = "failed";
            attempt.endedAt = timestamp(context.now);
            phase.state = "failed";
            document.state = "failed";
            document.lastEvent = "phase_failed";
            return publicStatus(save(document), error.message);
          }

          Object.assign(attempt, attemptFrom(metadata));
          phase.state = metadata.state;
          if (metadata.state === "completed") {
            document.state = "paused";
            document.lastEvent = "phase_completed";
            save(document);
            continue;
          }
          document.state = metadata.state === "cancelled" ? "cancelled" : "failed";
          document.lastEvent = metadata.state === "cancelled" ? "phase_cancelled" : "phase_failed";
          return publicStatus(save(document));
        }

        document.state = "completed";
        document.lastEvent = "audit_completed";
        return publicStatus(save(document));
      } finally {
        unlinkSignal();
        active.delete(auditId);
      }
    });
  }

  async function cancelAudit(auditId, context = {}) {
    const controller = active.get(auditId);
    if (controller) {
      controller.abort();
      return { auditId, state: "cancelling" };
    }
    return dependencies.withWorkflowLock(auditId, stateOptions(context), async () => {
      let document = dependencies.readAuditDocument(auditId, stateOptions(context));
      if (document.state === "completed") return publicStatus(document);
      for (const phase of document.phases) {
        if (phase.state !== "completed") phase.state = "cancelled";
      }
      document.state = "cancelled";
      document.lastEvent = "operator_cancelled";
      document = dependencies.writeAuditDocument(auditId, document, stateOptions(context));
      return publicStatus(document);
    });
  }

  return Object.freeze({ startAudit, resumeAudit, getAuditStatus, listAudits, cancelAudit });
}
