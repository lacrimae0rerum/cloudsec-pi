export const SCANNER_IDS = ["trivy", "docker-bench", "lynis", "prowler"];

export const COMMON_ENV_NAMES = ["PATH", "LANG", "LC_ALL", "TERM", "TMPDIR", "NO_COLOR"];
export const NETWORK_ENV_NAMES = [
  "SSL_CERT_FILE",
  "SSL_CERT_DIR",
  "REQUESTS_CA_BUNDLE",
  "HTTPS_PROXY",
  "HTTP_PROXY",
  "NO_PROXY",
];
export const CLOUDFLARE_ENV_NAMES = [
  "CLOUDFLARE_API_TOKEN",
  "CLOUDFLARE_API_KEY",
  "CLOUDFLARE_API_EMAIL",
];

export const SCANNERS = Object.freeze({
  trivy: Object.freeze({ command: "trivy", versionArgs: ["--version"], platforms: ["darwin", "linux"] }),
  "docker-bench": Object.freeze({ command: undefined, versionArgs: [], platforms: ["linux"] }),
  lynis: Object.freeze({ command: "lynis", versionArgs: ["show", "version"], platforms: ["linux"] }),
  prowler: Object.freeze({ command: "prowler", versionArgs: ["-v"], platforms: ["darwin", "linux"] }),
});

export function pickEnvironment(names, source = process.env, additions = {}) {
  const environment = {};
  for (const name of names) {
    const value = source[name];
    if (typeof value === "string" && value !== "") environment[name] = value;
  }
  return { ...environment, ...additions };
}
