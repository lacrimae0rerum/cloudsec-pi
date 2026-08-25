const SCANNERS = ["trivy", "docker-bench", "lynis", "prowler"];
const CONFIRM_TIMEOUT_MS = 300_000;

function notifyError(ctx, error) {
  ctx.ui.notify(error instanceof Error ? error.message : String(error), "error");
}

function requireTui(ctx, command) {
  if (ctx.mode === "tui") return true;
  ctx.ui.notify(`/${command} requires interactive TUI mode`, "error");
  return false;
}

function parseLimit(raw) {
  if (!raw?.trim()) return 10;
  const limit = Number(raw.trim());
  if (!Number.isInteger(limit) || limit < 1 || limit > 20) throw new Error("Status limit must be an integer from 1 to 20");
  return limit;
}

export function createControlUi(components) {
  const { BorderedLoader, Container, DynamicBorder, SelectList, SettingsList, Text, getSettingsListTheme } = components;
  return {
    async chooseAction(ctx, overview) {
      const items = [
        { value: "doctor", label: "Doctor", description: "Check scanner availability" },
        { value: "audit", label: "Audit", description: "Start or resume a combined audit" },
        { value: "status", label: "Status", description: "Show recent audits and scanner runs" },
        { value: "cancel", label: "Cancel", description: "Cancel a paused combined audit" },
      ];
      return ctx.ui.custom((tui, theme, _keybindings, done) => {
        const container = new Container();
        container.addChild(new DynamicBorder((text) => theme.fg("accent", text)));
        container.addChild(new Text(theme.fg("accent", theme.bold("Cloud security control centre")), 1, 0));
        container.addChild(new Text(theme.fg("muted", overview), 1, 0));
        const list = new SelectList(items, items.length, {
          selectedPrefix: (text) => theme.fg("accent", text),
          selectedText: (text) => theme.fg("accent", text),
          description: (text) => theme.fg("muted", text),
          scrollInfo: (text) => theme.fg("dim", text),
          noMatch: (text) => theme.fg("warning", text),
        });
        list.onSelect = (item) => done(item.value);
        list.onCancel = () => done(null);
        container.addChild(list);
        container.addChild(new DynamicBorder((text) => theme.fg("accent", text)));
        return {
          render: (width) => container.render(width),
          invalidate: () => container.invalidate(),
          handleInput: (data) => { list.handleInput(data); tui.requestRender(); },
        };
      });
    },

    async chooseScanners(ctx) {
      const enabled = new Set(["trivy"]);
      return ctx.ui.custom((tui, theme, _keybindings, done) => {
        const container = new Container();
        container.addChild(new Text(theme.fg("accent", theme.bold("Scanner selection")), 1, 0));
        container.addChild(new Text(theme.fg("dim", "Toggle scanners, then press Escape to continue"), 1, 0));
        const items = SCANNERS.map((scanner) => ({
          id: scanner,
          label: scanner,
          currentValue: enabled.has(scanner) ? "enabled" : "disabled",
          values: ["enabled", "disabled"],
        }));
        const settings = new SettingsList(
          items,
          items.length + 2,
          getSettingsListTheme(),
          (id, value) => value === "enabled" ? enabled.add(id) : enabled.delete(id),
          () => done(SCANNERS.filter((scanner) => enabled.has(scanner))),
        );
        container.addChild(settings);
        return {
          render: (width) => container.render(width),
          invalidate: () => container.invalidate(),
          handleInput: (data) => { settings.handleInput?.(data); tui.requestRender(); },
        };
      });
    },

    async run(ctx, message, operation) {
      const result = await ctx.ui.custom((tui, theme, _keybindings, done) => {
        const loader = new BorderedLoader(tui, theme, message);
        loader.onAbort = () => {};
        Promise.resolve()
          .then(() => operation(loader.signal))
          .then((value) => done({ value }))
          .catch((error) => done({ error }));
        return loader;
      });
      if (result?.error) throw result.error;
      return result?.value;
    },
  };
}

async function buildAuditRequest(ctx, controlUi) {
  const selected = await controlUi.chooseScanners(ctx);
  if (!selected || selected.length === 0) throw new Error("Select at least one scanner");
  const request = {};
  if (selected.includes("trivy")) {
    const target = await ctx.ui.select("Trivy target", ["Filesystem", "Container image"]);
    if (!target) return undefined;
    if (target === "Filesystem") {
      const path = await ctx.ui.input("Project-relative path", ".");
      if (path === undefined) return undefined;
      request.trivy = { target: "fs", path: path || "." };
    } else {
      const image = await ctx.ui.input("Container image reference");
      if (!image) return undefined;
      request.trivy = { target: "image", image };
    }
  }
  if (selected.includes("docker-bench")) {
    const mode = await ctx.ui.select("Docker Bench privilege", ["Unprivileged", "Privileged with sudo"]);
    if (!mode) return undefined;
    request.dockerBench = { privileged: mode === "Privileged with sudo" };
  }
  if (selected.includes("lynis")) {
    const mode = await ctx.ui.select("Lynis privilege", ["Unprivileged", "Privileged with sudo"]);
    if (!mode) return undefined;
    request.lynis = { privileged: mode === "Privileged with sudo" };
  }
  if (selected.includes("prowler")) request.prowler = { provider: "cloudflare" };
  return request;
}

export function registerControlCommands(pi, dependencies) {
  const { collectCloudsecStatus, controlUi, formatCloudsecStatus, formatScannerStatuses, inspectScanners, orchestrator } = dependencies;

  const showStatus = async (args, ctx) => {
    try {
      const status = collectCloudsecStatus({ env: process.env, limit: parseLimit(args) });
      ctx.ui.notify(formatCloudsecStatus(status), "info");
    } catch (error) {
      notifyError(ctx, error);
    }
  };

  const showDoctor = async (args, ctx) => {
    try {
      const scanner = args?.trim() || undefined;
      if (scanner && !SCANNERS.includes(scanner)) throw new Error(`Unknown scanner: ${scanner}`);
      ctx.ui.notify(formatScannerStatuses(await inspectScanners(scanner, { cwd: ctx.cwd })), "info");
    } catch (error) {
      notifyError(ctx, error);
    }
  };

  const runAudit = async (args, ctx) => {
    if (!requireTui(ctx, "cloudsec-audit")) return;
    try {
      let auditId = args?.trim();
      if (!auditId) {
        const request = await buildAuditRequest(ctx, controlUi);
        if (!request) return;
        const authorised = await ctx.ui.confirm(
          "Authorised audit scope",
          "Confirm that every selected target is owned by you or expressly authorised for this defensive assessment.",
          { timeout: CONFIRM_TIMEOUT_MS },
        );
        if (!authorised) return;
        auditId = orchestrator.startAudit(request, { cwd: ctx.cwd, env: process.env }).auditId;
      } else {
        orchestrator.getAuditStatus(auditId, { env: process.env });
        const authorised = await ctx.ui.confirm(
          "Resume authorised audit",
          "Confirm that the original targets remain owned by you or expressly authorised. Every risky scanner will ask again immediately before execution.",
          { timeout: CONFIRM_TIMEOUT_MS },
        );
        if (!authorised) return;
      }
      const result = await controlUi.run(ctx, `Running combined audit ${auditId}`, (signal) => orchestrator.resumeAudit(auditId, {
        cwd: ctx.cwd,
        env: process.env,
        mode: ctx.mode,
        signal,
        confirm: (title, body, options) => ctx.ui.confirm(title, body, options),
      }));
      ctx.ui.notify(`Audit ${result.auditId}: ${result.state}${result.message ? `; ${result.message}` : ""}`, result.state === "completed" ? "info" : "warning");
    } catch (error) {
      notifyError(ctx, error);
    }
  };

  const cancelAudit = async (args, ctx) => {
    if (!requireTui(ctx, "cloudsec-cancel")) return;
    try {
      let auditId = args?.trim();
      if (!auditId) {
        const { audits } = orchestrator.listAudits({ env: process.env, limit: 20 });
        const cancellable = audits.filter(({ state }) => !["completed", "cancelled"].includes(state));
        auditId = await ctx.ui.select("Cancel combined audit", cancellable.map(({ auditId: id }) => id));
      }
      if (!auditId) return;
      const confirmed = await ctx.ui.confirm("Cancel combined audit", `Cancel ${auditId}? Active scanner commands should be cancelled with Escape.`, { timeout: CONFIRM_TIMEOUT_MS });
      if (!confirmed) return;
      const result = await orchestrator.cancelAudit(auditId, { env: process.env });
      ctx.ui.notify(`Audit ${result.auditId}: ${result.state}`, "info");
    } catch (error) {
      notifyError(ctx, error);
    }
  };

  pi.registerCommand("cloudsec", {
    description: "Open the cloud security control centre",
    handler: async (_args, ctx) => {
      if (!requireTui(ctx, "cloudsec")) return;
      try {
        const status = collectCloudsecStatus({ env: process.env, limit: 5 });
        const action = await controlUi.chooseAction(ctx, `${status.audits.length} recent combined audit(s), ${status.runs.length} recent scanner run(s)`);
        if (action === "doctor") await showDoctor("", ctx);
        else if (action === "audit") await runAudit("", ctx);
        else if (action === "status") await showStatus("", ctx);
        else if (action === "cancel") await cancelAudit("", ctx);
      } catch (error) {
        notifyError(ctx, error);
      }
    },
  });
  pi.registerCommand("cloudsec-doctor", { description: "Check cloud security scanner availability", handler: showDoctor });
  pi.registerCommand("cloudsec-audit", { description: "Start or resume a private combined audit", handler: runAudit });
  pi.registerCommand("cloudsec-status", { description: "Show recent private audit status", handler: showStatus });
  pi.registerCommand("cloudsec-cancel", { description: "Cancel a combined audit", handler: cancelAudit });
}
