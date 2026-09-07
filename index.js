import { registerControlCommands } from "./lib/control-center.js";
import { formatScannerStatuses, inspectScanners } from "./lib/doctor.js";
import { readEvidence } from "./lib/evidence.js";
import { createOrchestrator } from "./lib/orchestrator.js";
import { formatPlan, preparePlan } from "./lib/plan.js";
import { recordPlanState, runPlan } from "./lib/runner.js";
import { runSetupProcess } from "./lib/setup.js";
import { collectCloudsecStatus, collectRunStatus, formatCloudsecStatus, formatRunStatus } from "./lib/status.js";

const CONFIRM_TIMEOUT_MS = 300_000;

async function executePlan(input, ctx, signal, dependencies) {
  const plan = dependencies.preparePlan(input, { cwd: ctx.cwd });
  if (plan.risk.requiresConfirmation) {
    if (ctx.mode !== "tui") {
      dependencies.recordPlanState(plan, "blocked");
      throw new Error("This audit requires TUI confirmation and was blocked");
    }
    const confirmed = await ctx.ui.confirm(
      "Confirm cloud security audit",
      dependencies.formatPlan(plan),
      { timeout: CONFIRM_TIMEOUT_MS, signal },
    );
    if (!confirmed) {
      const state = signal?.aborted ? "cancelled" : "declined";
      dependencies.recordPlanState(plan, state);
      return { content: [{ type: "text", text: `Audit ${plan.runId} was ${state}; no scanner ran.` }], details: { runId: plan.runId, state } };
    }
  }
  const metadata = await dependencies.runPlan(plan, { signal });
  return {
    content: [{ type: "text", text: `Audit ${metadata.runId} ${metadata.state} with exit code ${metadata.exitCode ?? "n/a"}. Use cloudsec_evidence to inspect redacted evidence.` }],
    details: { runId: metadata.runId, state: metadata.state, exitCode: metadata.exitCode },
  };
}

const fallbackControlUi = Object.freeze({
  chooseAction: async (ctx) => ctx.ui.select("Cloud security control centre", ["doctor", "setup", "audit", "status", "cancel"]),
  chooseScanners: async () => ["trivy"],
  run: async (_ctx, _message, operation) => operation(new AbortController().signal),
});

export function registerCloudsec(pi, schemas, overrides = {}) {
  const orchestrator = overrides.orchestrator ?? createOrchestrator(overrides);
  const dependencies = {
    collectCloudsecStatus,
    collectRunStatus,
    controlUi: fallbackControlUi,
    formatCloudsecStatus,
    formatPlan,
    formatRunStatus,
    formatScannerStatuses,
    inspectScanners,
    orchestrator,
    preparePlan,
    readEvidence,
    recordPlanState,
    runPlan,
    runSetupProcess,
    ...overrides,
  };
  const { Type, StringEnum } = schemas;

  pi.registerTool({
    name: "cloudsec_doctor",
    label: "Cloud security doctor",
    description: "Check supported scanner paths, versions and platform limitations without installing or changing anything",
    parameters: Type.Object({ scanner: Type.Optional(StringEnum(["trivy", "docker-bench", "lynis", "prowler"])) }, { additionalProperties: false }),
    async execute(_id, params, _signal, _update, ctx) {
      const statuses = await dependencies.inspectScanners(params.scanner, { cwd: ctx.cwd });
      return { content: [{ type: "text", text: dependencies.formatScannerStatuses(statuses) }], details: { statuses } };
    },
  });

  pi.registerTool({
    name: "cloudsec_trivy",
    label: "Trivy audit",
    description: "Run a private Trivy filesystem or image audit. Filesystem targets must stay inside the current project; image scans require confirmation.",
    parameters: Type.Object({
      target: StringEnum(["fs", "image"]),
      path: Type.Optional(Type.String({ description: "Project-relative filesystem target when target=fs" })),
      image: Type.Optional(Type.String({ description: "Container image reference when target=image" })),
    }, { additionalProperties: false }),
    execute(_id, params, signal, _update, ctx) {
      return executePlan({ scanner: "trivy", ...params }, ctx, signal, dependencies);
    },
  });

  pi.registerTool({
    name: "cloudsec_docker_bench",
    label: "Docker Bench audit",
    description: "Run Docker Bench against the local Linux Docker host using the operator-configured script path and integrity confirmation",
    parameters: Type.Object({ privileged: Type.Optional(Type.Boolean({ description: "Use non-interactive sudo; defaults to true" })) }, { additionalProperties: false }),
    execute(_id, params, signal, _update, ctx) {
      return executePlan({ scanner: "docker-bench", ...params }, ctx, signal, dependencies);
    },
  });

  pi.registerTool({
    name: "cloudsec_lynis",
    label: "Lynis audit",
    description: "Run Lynis against the local Linux host; privileged mode requires confirmation and non-interactive sudo",
    parameters: Type.Object({ privileged: Type.Optional(Type.Boolean()) }, { additionalProperties: false }),
    execute(_id, params, signal, _update, ctx) {
      return executePlan({ scanner: "lynis", ...params }, ctx, signal, dependencies);
    },
  });

  pi.registerTool({
    name: "cloudsec_prowler",
    label: "Prowler audit",
    description: "Run a confirmed read-only Prowler Cloudflare audit using native environment credentials; no secret values are accepted",
    parameters: Type.Object({ provider: StringEnum(["cloudflare"]) }, { additionalProperties: false }),
    execute(_id, params, signal, _update, ctx) {
      return executePlan({ scanner: "prowler", ...params }, ctx, signal, dependencies);
    },
  });

  pi.registerTool({
    name: "cloudsec_evidence",
    label: "Cloud security evidence",
    description: "Read redacted, traversal-safe evidence from a cloudsec-pi run. Output is limited to 50KB.",
    parameters: Type.Object({
      runId: Type.String(),
      file: StringEnum(["metadata", "stdout", "stderr", "report"]),
      maxBytes: Type.Optional(Type.Integer({ minimum: 1_024, maximum: 50_000 })),
    }, { additionalProperties: false }),
    async execute(_id, params) {
      const evidence = dependencies.readEvidence(params.runId, params.file, { maxBytes: params.maxBytes });
      return { content: [{ type: "text", text: evidence.text }], details: { runId: params.runId, file: params.file, truncated: evidence.truncated } };
    },
  });

  pi.registerTool({
    name: "cloudsec_status",
    label: "Cloud security status",
    description: "List recent private combined audits and scanner runs without exposing execution details or evidence content",
    parameters: Type.Object({ limit: Type.Optional(Type.Integer({ minimum: 1, maximum: 20 })) }, { additionalProperties: false }),
    async execute(_id, params) {
      const status = dependencies.collectCloudsecStatus({ limit: params.limit });
      return { content: [{ type: "text", text: dependencies.formatCloudsecStatus(status) }], details: status };
    },
  });

  registerControlCommands(pi, dependencies);
}
