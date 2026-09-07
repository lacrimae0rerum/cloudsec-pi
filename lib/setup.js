import { spawn } from "node:child_process";
import { lstatSync, mkdtempSync, readFileSync, realpathSync, rmSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, delimiter, isAbsolute, join, relative } from "node:path";
import { inspectScanner, resolveExecutable } from "./doctor.js";
import { CLOUDFLARE_ENV_NAMES, SCANNER_IDS } from "./scanners.js";
import { assertSafePath, configuredEnvironment, ensureSetupDir, PATH_NAMES, readSetupConfig, setupRoot, withToolLock, writeSetupConfig } from "./setup-config.js";

export const SETUP_TIMEOUT_MS = 300_000;
export const SOURCES = Object.freeze({
  trivy: "https://trivy.dev/docs/latest/getting-started/installation/",
  lynis: "https://cisofy.com/documentation/lynis/get-started/",
  prowler: "https://docs.prowler.com/getting-started/installation/prowler-cli",
  "docker-bench": "https://github.com/docker/docker-bench-security.git",
});

function trustedExecutable(command, options) {
  const path = (options.resolveExecutable ?? resolveExecutable)(command, options.env);
  if (!path) return undefined;
  assertSafePath(path);
  const project = realpathSync(options.cwd ?? process.cwd());
  const rel = relative(project, path);
  if (!rel.startsWith("../") && !isAbsolute(rel)) throw new Error("Project-local executables cannot perform setup");
  if (!lstatSync(path).isFile()) throw new Error("Setup executable must be a regular file");
  if (command === "brew") {
    const configs = ["/etc/homebrew/brew.env", join(dirname(dirname(path)), "etc/homebrew/brew.env"), "/usr/local/etc/homebrew/brew.env", join(setupRoot(options), "home/.homebrew/brew.env")];
    for (const config of configs) {
      try { lstatSync(config); throw new Error("Homebrew disk configuration present; manual installation required"); }
      catch (error) { if (error.code !== "ENOENT") throw error; }
    }
  }
  return path;
}

export function installerEnvironment(root, executable, environment = {}) {
  const paths = [dirname(executable), "/usr/bin", "/bin", "/usr/sbin", "/sbin"];
  // Only safe absolute PATH entries, never project-relative tools, proxies or provider credentials.
  for (const path of (environment.PATH ?? "").split(delimiter)) {
    if (isAbsolute(path) && ["/opt/homebrew/bin", "/usr/local/bin", "/home/linuxbrew/.linuxbrew/bin"].includes(path)) paths.push(path);
  }
  return {
    PATH: [...new Set(paths)].join(delimiter), HOME: join(root, "home"), TMPDIR: join(root, "tmp"),
    LANG: "C", LC_ALL: "C", NO_COLOR: "1", CI: "1",
    HOMEBREW_NO_AUTO_UPDATE: "1", HOMEBREW_NO_INSTALL_CLEANUP: "1", HOMEBREW_NO_ANALYTICS: "1", HOMEBREW_NO_INSTALL_UPGRADE: "1",
    PIPX_HOME: join(root, "pipx"), PIPX_BIN_DIR: join(root, "bin"), PIPX_MAN_DIR: join(root, "man"), PIP_CONFIG_FILE: "/dev/null", PIP_INDEX_URL: "https://pypi.org/simple",
    UV_TOOL_DIR: join(root, "uv-tools"), UV_TOOL_BIN_DIR: join(root, "bin"), UV_CACHE_DIR: join(root, "cache"),
    GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", GIT_TERMINAL_PROMPT: "0",
  };
}

export function setupRecipe(scanner, options = {}) {
  if (!SCANNER_IDS.includes(scanner)) throw new Error("Unknown setup scanner");
  const platform = options.platform ?? process.platform;
  if (!["darwin", "linux"].includes(platform) || (["lynis", "docker-bench"].includes(scanner) && platform !== "linux")) return { scanner, state: "unsupported", reason: "Local Linux only for host scanners; harness supports macOS/Linux" };
  const root = setupRoot(options);
  let executable;
  let args;
  let candidate;
  if (scanner === "docker-bench") {
    executable = trustedExecutable("git", options);
    candidate = join(root, "docker-bench", "docker-bench-security.sh");
    args = ["-c", "core.hooksPath=/dev/null", "clone", "--depth", "1", "--", SOURCES[scanner], dirname(candidate)];
  } else if (scanner === "prowler" && (executable = trustedExecutable("uv", options))) {
    args = ["tool", "install", "--no-config", "--no-python-downloads", "--default-index", "https://pypi.org/simple", "prowler"];
    candidate = join(root, "bin", "prowler");
  } else if (scanner === "prowler" && (executable = trustedExecutable("pipx", options))) {
    args = ["install", "prowler", "--index-url", "https://pypi.org/simple"];
    candidate = join(root, "bin", "prowler");
  } else {
    executable = trustedExecutable("brew", options);
    if (executable) { args = ["install", `homebrew/core/${scanner}`]; candidate = join(dirname(executable), scanner); }
  }
  if (!executable && platform === "linux" && ["lynis", "trivy"].includes(scanner)) {
    const apt = trustedExecutable("apt-get", options);
    const dnf = apt ? undefined : trustedExecutable("dnf", options);
    const manager = apt ?? dnf;
    if (manager) {
      const commands = scanner === "lynis" ? [`sudo ${manager} install lynis`] : apt ? [
        `sudo ${manager} install wget gnupg`,
        "wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null",
        "echo 'deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main' | sudo tee /etc/apt/sources.list.d/trivy.list",
        `sudo ${manager} update`, `sudo ${manager} install trivy`,
      ] : [
        "Create /etc/yum.repos.d/trivy.repo as root with: [trivy]\\nname=Trivy repository\\nbaseurl=https://aquasecurity.github.io/trivy-repo/rpm/releases/$basearch/\\ngpgcheck=1\\nenabled=1\\ngpgkey=https://aquasecurity.github.io/trivy-repo/rpm/public.key",
        `sudo ${manager} install trivy`,
      ];
      return { scanner, state: "manual", source: SOURCES[scanner], commands, reason: `Human terminal action required; review official repository/key instructions at ${SOURCES[scanner]} before running these privileged commands. No command is executed by Pi.` };
    }
  }
  if (!executable) return { scanner, state: "blocked", reason: scanner === "lynis"
    ? `No supported unprivileged manager. Human terminal: apt-get install lynis or dnf install lynis after reviewing official repository setup at ${SOURCES[scanner]}; privilege is human-mediated.`
    : `Missing prerequisite manager (${scanner === "docker-bench" ? "git" : scanner === "prowler" ? "uv, pipx or Homebrew" : "Homebrew"}). Install prerequisites manually using ${scanner === "prowler" ? "https://docs.astral.sh/uv/getting-started/installation/" : scanner === "docker-bench" ? "https://git-scm.com/downloads" : "https://docs.brew.sh/Installation"}, then rerun setup. Official scanner steps: ${SOURCES[scanner]}` };
  return Object.freeze({ scanner, state: "planned", executable, args: Object.freeze(args), candidate, source: SOURCES[scanner], root, executableHash: createHash("sha256").update(readFileSync(executable)).digest("hex") });
}

export function runSetupProcess(executable, args, options = {}) {
  if (options.signal?.aborted) return Promise.resolve({ state: "cancelled" });
  return new Promise((resolve) => {
    const child = spawn(executable, args, { cwd: options.cwd, env: options.env, shell: false, detached: process.platform !== "win32", stdio: ["ignore", "pipe", "pipe"] });
    let cancelled = false;
    let exceeded = false;
    let output = "";
    let bytes = 0;
    let killTimer;
    const kill = (signal) => {
      try { if (child.pid) process.kill(process.platform === "win32" ? child.pid : -child.pid, signal); }
      catch (error) { if (error.code !== "ESRCH") exceeded = true; }
    };
    const stop = () => {
      if (cancelled) return;
      cancelled = true;
      kill("SIGTERM");
      killTimer = setTimeout(() => kill("SIGKILL"), 500);
    };
    const collect = (chunk) => {
      bytes += chunk.length;
      if (bytes > 64 * 1024) { exceeded = true; stop(); }
      else if (options.capture) output += chunk.toString();
    };
    child.stdout.on("data", collect);
    child.stderr.on("data", collect);
    let failed = false;
    child.once("error", () => { failed = true; });
    const timer = setTimeout(() => { exceeded = true; stop(); }, options.timeout ?? 120_000);
    options.signal?.addEventListener("abort", stop, { once: true });
    if (options.signal?.aborted) stop();
    child.once("close", (code) => {
      // A cancelled process group may retain grandchildren after its leader exits.
      if (cancelled) kill("SIGKILL");
      clearTimeout(timer); clearTimeout(killTimer);
      options.signal?.removeEventListener("abort", stop);
      resolve({ state: exceeded || failed || (!cancelled && code !== 0) ? "failed" : cancelled ? "cancelled" : "completed", code, ...(options.capture && !exceeded ? { output } : {}) });
    });
  });
}

function preview(recipe) {
  return [`Source: ${recipe.source}`, `Executable: ${recipe.executable}`, `Arguments: ${JSON.stringify(recipe.args)}`,
    `Installer SHA-256 (integrity, not provenance): ${recipe.executableHash}`,
    `Effects: download packages/source and dependencies; execute package installation code; create private setup storage at ${recipe.root}; Homebrew may write its existing prefix/cache. No prerequisite manager, service start, upgrade request or cloud audit.`,
    "Installer environment: isolated HOME and temporary directory, safe PATH, fixed manager settings; no inherited credentials/proxies. Output is withheld, capped at 64 KiB; no retries."] .join("\n");
}

async function approve(options, title, body) {
  if (options.mode !== "tui" || typeof options.confirm !== "function" || options.signal?.aborted) return false;
  const now = options.now ?? Date.now;
  const start = now();
  const result = await options.confirm(title, body, { timeout: SETUP_TIMEOUT_MS, signal: options.signal });
  return result === true && !options.signal?.aborted && now() - start < SETUP_TIMEOUT_MS;
}

export async function inspectSetupReadiness(scanner, options = {}) {
  const status = await (options.inspectScanner ?? inspectScanner)(scanner, options);
  if (scanner === "prowler") return { ...status, authentication: CLOUDFLARE_ENV_NAMES.map((name) => `${name}: ${options.env?.[name] ? "present" : "absent"}`).join(", ") + "; authentication and permissions unverified" };
  if (scanner !== "docker-bench" || !status.supported) return { ...status, capabilities: scanner === "lynis" ? "local host audit privileges unverified" : "database/network access and scan capabilities unverified" };
  const docker = trustedExecutable("docker", options);
  let daemon = "unavailable";
  if (docker) {
    const result = await runSetupProcess(docker, ["--host", "unix:///var/run/docker.sock", "version", "--format", "{{.Server.Version}}"], {
      cwd: "/", env: { PATH: "/usr/bin:/bin", LANG: "C" }, signal: options.signal, capture: true, timeout: 5000,
    });
    if (result.state === "completed" && /^\d+\.\d+/.test(result.output?.trim())) daemon = "local daemon accessible; audit privileges unverified";
  }
  return { ...status, daemon, dependencies: "sh and local host utilities required; jq recommended; audit permissions unverified" };
}

async function rememberPath(scanner, candidate, options, provenance = "") {
  if (Object.hasOwn(options.env ?? process.env, PATH_NAMES[scanner])) return "reused";
  if (readSetupConfig(options).paths[scanner] === candidate) return "reused";
  if (!await approve(options, `Remember ${scanner} path?`, `Write non-secret ${join(setupRoot(options), "config.json")} (0600 under 0700 directories): ${scanner} = ${candidate}\n${provenance}\nNo credentials or profile changes. Environment overrides remain explicit.`)) return "installed-not-configured";
  await withToolLock(options, async () => {
    assertSafePath(candidate);
    const config = readSetupConfig(options);
    config.paths[scanner] = candidate;
    writeSetupConfig(config, options);
  });
  return "configured";
}

export async function runSetup(selected, options = {}) {
  if (options.mode !== "tui") throw new Error("Scanner setup requires interactive TUI mode");
  if (!Array.isArray(selected) || !selected.length || new Set(selected).size !== selected.length || selected.some((id) => !SCANNER_IDS.includes(id))) throw new Error("Invalid scanner selection");
  const outcomes = selected.map((scanner) => ({ scanner, state: "pending" }));
  for (const outcome of outcomes) {
    if (options.signal?.aborted) { outcome.state = "cancelled"; break; }
    const scanner = outcome.scanner;
    try {
      const env = configuredEnvironment(options);
      const context = { ...options, env };
      let status = await inspectSetupReadiness(scanner, context);
      if (!status.path && !Object.hasOwn(env, PATH_NAMES[scanner]) && status.supported) {
        const managed = scanner === "docker-bench" ? join(setupRoot(options), "docker-bench", "docker-bench-security.sh") : join(setupRoot(options), "bin", scanner);
        try {
          const path = realpathSync(managed); assertSafePath(path);
          status = await inspectSetupReadiness(scanner, { ...context, env: { ...env, [PATH_NAMES[scanner]]: path } });
        } catch (error) { if (error.code !== "ENOENT") throw error; }
      }
      if (!status.supported) { Object.assign(outcome, { state: "unsupported", status }); continue; }
      if (!status.path && Object.hasOwn(env, PATH_NAMES[scanner])) {
        Object.assign(outcome, { state: "blocked", reason: `Explicit ${PATH_NAMES[scanner]} could not be probed; fix it outside Pi` });
        continue;
      }
      if (status.path) {
        Object.assign(outcome, { state: status.available ? await rememberPath(scanner, status.path, options, status.version) : "blocked", status });
        if (outcome.state === "installed-not-configured") break;
        continue; // Failed probes never authorise an overwrite or upgrade.
      }
      const recipe = setupRecipe(scanner, context);
      if (recipe.state === "manual") {
        const action = options.manualStep ? await options.manualStep(recipe) : "skip";
        if (action !== true) {
          Object.assign(outcome, { ...recipe, state: action === "skip" ? "blocked" : "cancelled" });
          if (outcome.state === "cancelled") break;
          continue;
        }
        const rechecked = await inspectSetupReadiness(scanner, context);
        Object.assign(outcome, { status: rechecked, state: rechecked.available ? await rememberPath(scanner, rechecked.path, options, rechecked.version) : "blocked" });
        if (!rechecked.available || outcome.state === "installed-not-configured") break;
        continue;
      }
      if (recipe.state !== "planned") { Object.assign(outcome, recipe); continue; }
      if (!await approve(options, `Install ${scanner}?`, preview(recipe))) { outcome.state = options.signal?.aborted ? "cancelled" : "declined"; break; }
      const result = await withToolLock(options, async () => {
        const current = await inspectScanner(scanner, context);
        if (current.path) throw new Error("Scanner appeared after preview; rerun setup to reuse it");
        assertSafePath(recipe.executable);
        trustedExecutable(recipe.args[0] === "install" ? recipe.args[1] === "prowler" ? "pipx" : "brew" : recipe.args[0] === "tool" ? "uv" : "git", context);
        if (createHash("sha256").update(readFileSync(recipe.executable)).digest("hex") !== recipe.executableHash) throw new Error("Installer changed after preview");
        for (const path of [recipe.root, join(recipe.root, "home"), join(recipe.root, "tmp")]) ensureSetupDir(path);
        if (scanner === "docker-bench" || recipe.args[0] === "tool" || recipe.args[1] === "prowler") {
          const target = scanner === "docker-bench" ? dirname(recipe.candidate) : join(recipe.root, recipe.args[1] === "prowler" ? "pipx" : "uv-tools");
          try { lstatSync(target); throw new Error("Managed install target exists; inspect it manually, no overwrite or automatic retry"); }
          catch (error) { if (error.code !== "ENOENT") throw error; }
        }
        const work = mkdtempSync(join(recipe.root, "tmp", "install-"));
        try {
          const installerEnv = installerEnvironment(recipe.root, recipe.executable, env);
          const execute = options.execute ?? runSetupProcess;
          const installed = await execute(recipe.executable, recipe.args, { cwd: work, env: installerEnv, signal: options.signal });
          if (installed.state !== "completed") return installed;
          let candidatePath = recipe.candidate;
          if (recipe.args[0] === "install" && recipe.args[1] !== "prowler") {
            const prefix = await execute(recipe.executable, ["--prefix", scanner], { cwd: work, env: installerEnv, signal: options.signal, capture: true });
            if (prefix.state !== "completed") return prefix;
            const prefixPath = prefix.output?.trim();
            if (!isAbsolute(prefixPath ?? "") || /[\x00-\x1f\x7f]/.test(prefixPath)) throw new Error("Invalid manager prefix");
            candidatePath = join(assertSafePath(realpathSync(prefixPath)), "bin", scanner);
          }
          const candidate = realpathSync(candidatePath);
          assertSafePath(candidate);
          if (scanner === "docker-bench") {
            const identity = createHash("sha256").update(readFileSync(candidate)).digest("hex");
            const commit = await execute(recipe.executable, ["-C", dirname(candidate), "rev-parse", "HEAD"], { cwd: work, env: installerEnv, signal: options.signal, capture: true });
            if (commit.state !== "completed" || !/^[a-f0-9]{40,64}$/.test(commit.output?.trim())) throw new Error("Cannot verify cloned source revision");
            outcome.source = `${SOURCES[scanner]} revision ${commit.output.trim()}; script SHA-256 ${identity}; hash is integrity, not proof of provenance`;
          }
          return { state: "installed", candidate };
        } finally { rmSync(work, { recursive: true, force: true }); }
      });
      outcome.state = result.state;
      if (result.state !== "installed") break;
      const nextEnv = { ...env, [PATH_NAMES[scanner]]: result.candidate };
      outcome.status = await inspectSetupReadiness(scanner, { ...context, env: nextEnv });
      if (!outcome.status.available) { outcome.state = "blocked"; break; }
      if (Object.hasOwn(options.env ?? process.env, PATH_NAMES[scanner])) {
        outcome.state = "blocked"; outcome.reason = `Explicit ${PATH_NAMES[scanner]} overrides setup; update it outside Pi`; break;
      }
      outcome.state = await rememberPath(scanner, result.candidate, options, outcome.source ?? outcome.status.version);
      if (outcome.state === "installed-not-configured") break;
    } catch (error) {
      // Do not surface arbitrary manager/config contents or child output into TUI/logs.
      outcome.state = "blocked";
      const safeReasons = ["Unsafe setup path", "Unsafe setup path permissions or symlink", "Setup storage must be private and user-owned", "Invalid setup configuration", "Unknown setup configuration key", "Installer changed after preview", "Project-local executables cannot perform setup", "Managed install target exists; inspect it manually, no overwrite or automatic retry", "Scanner appeared after preview; rerun setup to reuse it", "Cannot verify cloned source revision", "Homebrew disk configuration present; manual installation required", "Scanner/setup execution locked; inspect active processes before manually removing a stale lock"];
      outcome.reason = `${safeReasons.includes(error.message) ? error.message : ["ENOENT", "EACCES", "EPERM"].includes(error.code) ? error.code : "Setup validation or execution failed"}. No retry; partial manager state may remain.`;
      break;
    }
  }
  return outcomes;
}

export async function chooseSetupScanners(ctx) {
  const choice = await ctx.ui.select("Scanner setup", ["All scanners", "Choose some", "Cancel"]);
  if (!choice || choice === "Cancel") return undefined;
  if (choice === "All scanners") return [...SCANNER_IDS];
  if (choice !== "Choose some") return undefined;
  const selected = [];
  while (true) {
    const remaining = SCANNER_IDS.filter((id) => !selected.includes(id));
    const next = await ctx.ui.select("Select scanners, then Continue", [...remaining, "Continue", "Cancel"]);
    if (!next || next === "Cancel") return undefined;
    if (next === "Continue") return selected.length ? selected : undefined;
    if (!remaining.includes(next)) return undefined;
    selected.push(next);
  }
}

export function formatSetupOutcomes(outcomes) {
  return outcomes.map((item) => `${item.scanner}: ${item.state}${item.reason ? `; ${item.reason}` : ""}${item.commands ? `\n${item.commands.join("\n")}` : ""}${item.status?.version ? `; ${item.status.version}` : ""}${item.status?.reason ? `; ${item.status.reason}` : ""}${item.status?.authentication ? `; ${item.status.authentication}` : ""}${item.status?.capabilities ? `; ${item.status.capabilities}` : ""}${item.status?.daemon ? `; ${item.status.daemon}; ${item.status.dependencies}` : ""}${item.source ? `; ${item.source}` : ""}`).join("\n") + "\nCloudflare credentials: provide CLOUDFLARE_API_TOKEN (preferred), or CLOUDFLARE_API_KEY and CLOUDFLARE_API_EMAIL through your native environment/secret manager before starting Pi. Never enter secret values here. Authentication/audit is separate and requires confirmation; no full-readiness claim.";
}
