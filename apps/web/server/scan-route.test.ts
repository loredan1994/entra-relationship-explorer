import { NextRequest } from "next/server";
import { beforeEach, expect, it, vi } from "vitest";

const TENANT = "11111111-1111-4111-8111-111111111111";
const JOB = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const getServerSession = vi.fn();
const getJob = vi.fn();
const requestScanCancellation = vi.fn();

vi.mock("./config", () => ({ getEntraConfig: () => ({ enabled: true, tenantId: TENANT, redirectUri: "http://127.0.0.1:3200/api/auth/callback" }) }));
vi.mock("./backend", () => ({ getBackend: async () => ({ getJob, requestScanCancellation }) }));
vi.mock("./auth/session-store", () => ({ SESSION_COOKIE: "entra_explorer_session", getServerSession: (...args: unknown[]) => getServerSession(...args) }));

const route = await import("../app/api/scans/[id]/route");
const request = (method: string, origin = "http://127.0.0.1:3200") => new NextRequest(`http://127.0.0.1:3200/api/scans/${JOB}`, { method, headers: { origin } });

beforeEach(() => {
  vi.resetAllMocks();
  getServerSession.mockResolvedValue({ id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", tenantId: TENANT });
});

it.each(["GET", "DELETE"] as const)("%s rejects malformed IDs before a PostgreSQL lookup", async method => {
  for (const id of ["invalid", "", `${JOB}\n`, `prefix-${JOB}`, JOB.replaceAll("-", "")]) {
    const response = await route[method](request(method), { params: Promise.resolve({ id }) });
    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({ error: method === "GET" ? "Scan job not found." : "Active scan job not found." });
    expect(response.headers.get("cache-control")).toBe("no-store, private");
  }
  expect(getJob).not.toHaveBeenCalled();
  expect(requestScanCancellation).not.toHaveBeenCalled();
});

it.each(["GET", "DELETE"] as const)("%s requires a tenant session before validating the ID", async method => {
  for (const session of [null, { tenantId: "22222222-2222-4222-8222-222222222222" }]) {
    getServerSession.mockResolvedValue(session);
    const response = await route[method](request(method), { params: Promise.resolve({ id: "invalid" }) });
    expect(response.status).toBe(401);
  }
  expect(getJob).not.toHaveBeenCalled();
  expect(requestScanCancellation).not.toHaveBeenCalled();
});

it.each(["GET", "DELETE"] as const)("%s canonicalizes valid uppercase IDs and preserves tenant scoping", async method => {
  const job = { id: JOB, tenantId: TENANT, status: "cancel_requested" };
  getJob.mockResolvedValue(job);
  requestScanCancellation.mockResolvedValue(job);
  const response = await route[method](request(method), { params: Promise.resolve({ id: JOB.toUpperCase() }) });
  expect(response.status).toBe(method === "GET" ? 200 : 202);
  expect(await response.json()).toEqual({ job });
  expect(method === "GET" ? getJob : requestScanCancellation).toHaveBeenCalledExactlyOnceWith(JOB, TENANT);
});

it("rejects cross-origin cancellation before session or identifier handling", async () => {
  const response = await route.DELETE(request("DELETE", "https://attacker.example"), { params: Promise.resolve({ id: "invalid" }) });
  expect(response.status).toBe(403);
  expect(getServerSession).not.toHaveBeenCalled();
  expect(requestScanCancellation).not.toHaveBeenCalled();
});
