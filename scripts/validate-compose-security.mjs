#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
// Compose requires every interpolated variable to resolve before it will render
// the configuration. These placeholders exist only so the isolation checks below
// can run; none of them is a real credential, and the tenant identifiers are
// deliberately synthetic so no contributor's tenant leaks into a check.
const safeEnvironment = {
  ...process.env,
  ENTRA_TENANT_ID: process.env.ENTRA_TENANT_ID ?? "11111111-1111-4111-8111-111111111111",
  ENTRA_CLIENT_ID: process.env.ENTRA_CLIENT_ID ?? "11111111-1111-4111-8111-111111111112",
  ENTRA_CLIENT_SECRET: "validation-placeholder-not-a-secret",
  ENTRA_DATA_ENCRYPTION_KEY: "validation-placeholder-not-a-key",
  POSTGRES_PASSWORD: "validation-placeholder-not-a-password",
  POSTGRES_PASSWORD_URL_ENCODED: "validation-placeholder-not-a-password",
};

const rendered = spawnSync("docker", ["compose", "config", "--format", "json"], {
  cwd: root,
  env: safeEnvironment,
  encoding: "utf8",
});

if (rendered.status !== 0) {
  process.stderr.write(rendered.stderr || "docker compose config failed\n");
  process.exit(rendered.status || 1);
}

const config = JSON.parse(rendered.stdout);
const errors = [];

// New workspace packages must join the manifest-only install layer. Otherwise a
// cached image can silently retain an incomplete dependency tree after COPY . .
const dockerInstructions = readFileSync(path.join(root, "Dockerfile"), "utf8")
  .replace(/\\\r?\n/g, " ")
  .split(/\r?\n/)
  .map((line) => line.trim())
  .filter((line) => line && !line.startsWith("#"));
const dependencyInstall = dockerInstructions.findIndex((line) => /^RUN\s+pnpm install --frozen-lockfile$/.test(line));
const sourceCopy = dockerInstructions.findIndex((line) => /^COPY\s+\.\s+\.$/.test(line));
if (dependencyInstall < 0 || sourceCopy <= dependencyInstall) {
  errors.push("Docker must install frozen dependencies before copying product source");
}
const dependencyInputs = new Set(dockerInstructions.slice(0, Math.max(0, dependencyInstall))
  .filter((line) => line.startsWith("COPY "))
  .flatMap((line) => line.split(/\s+/).slice(1, -1)));
const workspaceManifests = ["apps", "packages"].flatMap((directory) =>
  readdirSync(path.join(root, directory), { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && existsSync(path.join(root, directory, entry.name, "package.json")))
    .map((entry) => `${directory}/${entry.name}/package.json`));
for (const input of ["package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml", "patches", ...workspaceManifests]) {
  if (!dependencyInputs.has(input)) errors.push(`Docker dependency layer is missing ${input}`);
}
const ignoredBuildInputs = new Set(readFileSync(path.join(root, ".dockerignore"), "utf8")
  .split(/\r?\n/).map((line) => line.trim()));
for (const input of [".pnpm-store", "**/.pnpm-store", "**/.env", "**/.env.*"]) {
  if (!ignoredBuildInputs.has(input)) errors.push(`Docker build context must exclude ${input}`);
}
const requiredServices = ["postgres", "migrate", "web", "worker"];

for (const serviceName of requiredServices) {
  const service = config.services?.[serviceName];
  if (!service) {
    errors.push(`missing required service: ${serviceName}`);
    continue;
  }
  if (service.privileged === true) errors.push(`${serviceName} must not be privileged`);
  if (service.network_mode === "host") errors.push(`${serviceName} must not use the host network`);
  if (service.pid === "host" || service.ipc === "host") errors.push(`${serviceName} must not share host PID/IPC`);
  if (!(service.security_opt ?? []).includes("no-new-privileges:true")) {
    errors.push(`${serviceName} must enable no-new-privileges`);
  }
}

for (const serviceName of ["migrate", "worker"]) {
  if ((config.services?.[serviceName]?.ports ?? []).length > 0) {
    errors.push(`${serviceName} must not publish host ports`);
  }
}

for (const variable of ["ENTRA_CLIENT_SECRET", "ENTRA_CLIENT_ID", "ENTRA_TENANT_ID", "ENTRA_OPTIONAL_GRAPH_SCOPES"]) {
  if (variable in (config.services?.migrate?.environment ?? {})) errors.push(`migrate must not receive ${variable}`);
}

for (const [serviceName, expectedPort] of [["web", 3200], ["postgres", 54320]]) {
  const published = config.services?.[serviceName]?.ports ?? [];
  if (published.length !== 1) {
    errors.push(`${serviceName} must publish exactly one loopback port`);
    continue;
  }
  const port = published[0];
  if (port.host_ip !== "127.0.0.1" || Number(port.published) !== expectedPort) {
    errors.push(`${serviceName} must bind ${expectedPort} to 127.0.0.1 only`);
  }
}

const postgresImage = config.services?.postgres?.image ?? "";
if (!/^postgres:17-alpine@sha256:[a-f0-9]{64}$/.test(postgresImage)) {
  errors.push("postgres image must use the reviewed immutable digest");
}

if (config.services?.web?.image !== "entra-relationship-explorer-app:local") {
  errors.push("web must use the locally built application image");
}

if (errors.length > 0) {
  for (const error of errors) process.stderr.write(`compose security invariant failed: ${error}\n`);
  process.exit(1);
}

process.stdout.write("Compose security invariants valid: loopback exposure only, no privileged/host namespaces, worker and migration unpublished; Docker dependency inputs are cached before source.\n");
