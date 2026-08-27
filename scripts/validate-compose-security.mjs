#!/usr/bin/env node

import { spawnSync } from "node:child_process";
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

process.stdout.write("Compose security invariants valid: loopback exposure only, no privileged/host namespaces, worker and migration unpublished.\n");
