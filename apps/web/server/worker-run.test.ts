import { randomUUID } from "node:crypto";
import { MemoryBackend, type DurableSession } from "@entra-explorer/backend";
import { cleanProjectFixture } from "@entra-explorer/domain";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { LiveEntraConfig } from "./config-core";
import { runScanJob } from "./worker-run";

const acquireSilent = vi.hoisted(() => vi.fn());
vi.mock("./auth/msal", () => ({ acquireSilent }));

const tenantId = "11111111-1111-4111-8111-111111111111";
const config: LiveEntraConfig = { enabled: true, tenantId, clientId: "22222222-2222-4222-8222-222222222222", clientSecret: "synthetic-only", redirectUri: "http://127.0.0.1:3200/api/auth/callback", authority: `https://login.microsoftonline.com/${tenantId}`, scopes: ["Application.Read.All", "Directory.Read.All"], graphScopes: ["Application.Read.All", "Directory.Read.All"], databaseUrl: "unused", dataEncryptionKey: new Uint8Array(32), sessionMaxAgeSeconds: 3600 };
let backend: MemoryBackend;
let session: DurableSession;

beforeEach(async () => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2026-10-09T12:00:00.000Z"));
  acquireSilent.mockReset();
  backend = new MemoryBackend();
  session = { id: randomUUID(), tenantId, account: { tenantId }, accessToken: "synthetic-cached", accessTokenExpiresAt: Date.now() + 3600000, tokenCache: "synthetic-cache", sessionExpiresAt: Date.now() + 60000 };
  await backend.createSession(session);
});
afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

async function claim() {
  await backend.enqueueScan(tenantId, session.id);
  return (await backend.claimNextJob("original-worker", tenantId))!;
}

// The transport is always synthetic and GET-only. These tests drive the real
// scanner, token callback and backend, including interruptions after HTTP headers.
describe("scan worker session and lease boundaries", () => {
  it.each(["expiry", "sign-out"] as const)("stops after session %s without publishing cached-token reads", async interruption => {
    const job = await claim();
    const fetchImpl = vi.fn<typeof fetch>(async () => {
      if (interruption === "expiry") vi.setSystemTime(Date.now() + 60001);
      else await backend.deleteSession(session.id, tenantId);
      return Response.json({ value: [] });
    });
    vi.stubGlobal("fetch", fetchImpl);

    await expect(runScanJob(backend, job, "original-worker", config)).resolves.toBeUndefined();
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(await backend.getJob(job.id, tenantId)).toMatchObject({ status: "failed", snapshotId: null });
    expect(await backend.recentSnapshots(tenantId)).toEqual([]);
    expect(await backend.getScanCheckpoint(job.id, tenantId)).toBeNull();
    expect(acquireSilent).not.toHaveBeenCalled();
  });

  it("yields safely when a replacement worker claims an expired lease", async () => {
    session.sessionExpiresAt = Date.now() + 3600000;
    await backend.updateSession(session);
    const job = await claim();
    const fetchImpl = vi.fn<typeof fetch>(async () => {
      vi.setSystemTime(Date.now() + 11 * 60000);
      await backend.recoverStaleJobs(tenantId, new Date(Date.now() - 10 * 60000));
      await backend.claimNextJob("replacement-worker", tenantId);
      return Response.json({ value: [] });
    });
    vi.stubGlobal("fetch", fetchImpl);

    await expect(runScanJob(backend, job, "original-worker", config)).resolves.toBeUndefined();
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(await backend.getJob(job.id, tenantId)).toMatchObject({ status: "running", workerId: "replacement-worker", snapshotId: null, error: null });
    expect(await backend.recentSnapshots(tenantId)).toEqual([]);
    expect(await backend.getScanCheckpoint(job.id, tenantId)).toBeNull();
  });
});

it("publishes a successful read-only scan and clears its checkpoints", async () => {
  const job = await claim();
  const fetchImpl = vi.fn<typeof fetch>(async () => Response.json({ value: [] }));
  vi.stubGlobal("fetch", fetchImpl);
  await runScanJob(backend, job, "original-worker", config);
  const snapshots = await backend.recentSnapshots(tenantId);
  expect(snapshots).toHaveLength(1);
  expect(snapshots[0]!.tenant.tenantId).toBe(tenantId);
  expect(snapshots[0]!.completion.status).toBe("complete");
  expect(await backend.getJob(job.id, tenantId)).toMatchObject({ status: "complete", snapshotId: snapshots[0]!.id, workerId: null });
  expect(await backend.getScanCheckpoint(job.id, tenantId)).toBeNull();
  expect(fetchImpl).toHaveBeenCalledTimes(8);
  for (const [, options] of fetchImpl.mock.calls) expect(options).toMatchObject({ method: "GET", cache: "no-store", redirect: "error" });
  expect(vi.getTimerCount()).toBe(0);
});

it.each(["before collection", "after headers"] as const)("finishes requested cancellation %s and deletes unpublished checkpoints", async moment => {
  const job = await claim();
  if (moment === "before collection") {
    await backend.saveScanCheckpoint({ jobId: job.id, tenantId, payload: { syntheticEvidence: "unpublished" }, updatedAt: "" }, "original-worker");
    await backend.requestScanCancellation(job.id, tenantId);
    await backend.deleteSession(session.id, tenantId);
  }
  const fetchImpl = vi.fn<typeof fetch>(async () => {
    await backend.requestScanCancellation(job.id, tenantId);
    return Response.json({ value: [] });
  });
  vi.stubGlobal("fetch", fetchImpl);
  await runScanJob(backend, job, "original-worker", config);
  expect(fetchImpl).toHaveBeenCalledTimes(moment === "before collection" ? 0 : 1);
  expect(await backend.getJob(job.id, tenantId)).toMatchObject({ status: "cancelled", snapshotId: null });
  expect(await backend.getScanCheckpoint(job.id, tenantId)).toBeNull();
  expect(await backend.recentSnapshots(tenantId)).toEqual([]);
});

it("rechecks the session after collection, before publishing normalized evidence", async () => {
  const job = await claim();
  const progress = backend.updateJobProgress.bind(backend);
  vi.spyOn(backend, "updateJobProgress").mockImplementation(async (...args) => {
    await progress(...args);
    if (args[2] === "normalizing") await backend.deleteSession(session.id, tenantId);
  });
  vi.stubGlobal("fetch", vi.fn<typeof fetch>(async () => Response.json({ value: [] })));
  await runScanJob(backend, job, "original-worker", config);
  expect(await backend.getJob(job.id, tenantId)).toMatchObject({ status: "failed", snapshotId: null, error: expect.stringContaining("session expired or was signed out") });
  expect(await backend.recentSnapshots(tenantId)).toEqual([]);
});

it.each(["revoked", "expired"] as const)("refuses publication if the session is %s immediately after the final worker guard", async reason => {
  const job = await claim();
  const publish = backend.completeJob.bind(backend);
  vi.spyOn(backend, "completeJob").mockImplementation(async (...args) => {
    if (reason === "revoked") await backend.deleteSession(session.id, tenantId);
    else vi.setSystemTime(Date.now() + 60001);
    return publish(...args);
  });
  vi.stubGlobal("fetch", vi.fn<typeof fetch>(async () => Response.json({ value: [] })));
  await runScanJob(backend, job, "original-worker", config);
  expect(await backend.getJob(job.id, tenantId)).toMatchObject({ status: "failed", snapshotId: null });
  expect(await backend.recentSnapshots(tenantId)).toEqual([]);
  expect(await backend.getScanCheckpoint(job.id, tenantId)).toBeNull();
});

it.each(["lease replacement", "cancellation"] as const)("handles %s that wins between terminal-state read and write", async change => {
  session.sessionExpiresAt = Date.now() + 3600000;
  await backend.updateSession(session);
  const job = await claim();
  vi.spyOn(backend, "getScanCheckpoint").mockRejectedValue(new Error("Synthetic checkpoint unavailable"));
  const fail = backend.failJob.bind(backend);
  vi.spyOn(backend, "failJob").mockImplementation(async (...args) => {
    if (change === "cancellation") await backend.requestScanCancellation(job.id, tenantId);
    else {
      vi.setSystemTime(Date.now() + 11 * 60000);
      await backend.recoverStaleJobs(tenantId, new Date(Date.now() - 10 * 60000));
      await backend.claimNextJob("replacement-worker", tenantId);
    }
    return fail(...args);
  });
  await expect(runScanJob(backend, job, "original-worker", config)).resolves.toBeUndefined();
  expect(await backend.getJob(job.id, tenantId)).toMatchObject(change === "cancellation"
    ? { status: "cancelled", workerId: null }
    : { status: "running", workerId: "replacement-worker", error: null });
});

it("propagates a genuine terminal-write failure while retaining recoverable ownership", async () => {
  const job = await claim();
  vi.spyOn(backend, "getScanCheckpoint").mockRejectedValue(new Error("Synthetic checkpoint unavailable"));
  const databaseError = new Error("Synthetic database unavailable");
  vi.spyOn(backend, "failJob").mockRejectedValue(databaseError);
  await expect(runScanJob(backend, job, "original-worker", config)).rejects.toBe(databaseError);
  expect(await backend.getJob(job.id, tenantId)).toMatchObject({ status: "running", workerId: "original-worker" });
  expect(vi.getTimerCount()).toBe(0);
});

it.each(["denied", "unavailable"] as const)("stops a pending read after heartbeat is %s without overwriting the job", async result => {
  const job = await claim();
  const heartbeat = vi.spyOn(backend, "heartbeatJob");
  if (result === "denied") heartbeat.mockResolvedValue(false);
  else heartbeat.mockRejectedValue(new Error("Synthetic heartbeat outage"));
  let release!: (response: Response) => void;
  const pendingResponse = new Promise<Response>(resolve => { release = resolve; });
  const fetchImpl = vi.fn<typeof fetch>(async () => pendingResponse);
  vi.stubGlobal("fetch", fetchImpl);
  const run = runScanJob(backend, job, "original-worker", config);
  await vi.waitFor(() => expect(fetchImpl).toHaveBeenCalledTimes(1));
  await vi.advanceTimersByTimeAsync(30000);
  release(Response.json({ value: [] }));
  await run;
  expect(await backend.getJob(job.id, tenantId)).toMatchObject({ status: "running", workerId: "original-worker", snapshotId: null });
  expect(vi.getTimerCount()).toBe(0);
});

it.each(["dated", "missing expiry"] as const)("refreshes the token once and uses it for subsequent pages (%s)", async expiry => {
  session.accessTokenExpiresAt = Date.now() + 5 * 60000;
  await backend.updateSession(session);
  const job = await claim();
  acquireSilent.mockResolvedValue({ result: { accessToken: "synthetic-refreshed", expiresOn: expiry === "dated" ? new Date(Date.now() + 3600000) : null }, tokenCache: "synthetic-new-cache" });
  const fetchImpl = vi.fn<typeof fetch>(async () => Response.json({ value: [] }));
  vi.stubGlobal("fetch", fetchImpl);
  await runScanJob(backend, job, "original-worker", config);
  expect(acquireSilent).toHaveBeenCalledExactlyOnceWith(config, session.account, "synthetic-cache");
  expect(await backend.getSession(session.id, tenantId)).toMatchObject({ accessToken: "synthetic-refreshed", tokenCache: "synthetic-new-cache", accessTokenExpiresAt: Date.now() + (expiry === "dated" ? 60 : 55) * 60000 });
  for (const [, options] of fetchImpl.mock.calls) expect(options?.headers).toMatchObject({ Authorization: "Bearer synthetic-refreshed" });
  expect(await backend.getJob(job.id, tenantId)).toMatchObject({ status: "complete" });
});

it.each([null, { result: { accessToken: "" }, tokenCache: "synthetic" }])("stops a refused token refresh before Graph reads or partial publication: %j", async refused => {
  session.accessTokenExpiresAt = Date.now();
  await backend.updateSession(session);
  const job = await claim();
  acquireSilent.mockResolvedValue(refused);
  const fetchImpl = vi.fn<typeof fetch>();
  vi.stubGlobal("fetch", fetchImpl);
  await runScanJob(backend, job, "original-worker", config);
  expect(acquireSilent).toHaveBeenCalledTimes(1);
  expect(fetchImpl).not.toHaveBeenCalled();
  expect(await backend.getJob(job.id, tenantId)).toMatchObject({ status: "failed", snapshotId: null });
});

it("keeps a healthy lease alive while saving a slow checkpoint and then completes the scan", async () => {
  session.sessionExpiresAt = Date.now() + 3600000;
  await backend.updateSession(session);
  const job = await claim();
  let release!: () => void;
  const waiting = new Promise<void>(resolve => { release = resolve; });
  const save = backend.saveScanCheckpoint.bind(backend);
  let pending = false;
  vi.spyOn(backend, "saveScanCheckpoint").mockImplementation(async (...args) => {
    if (!pending) { pending = true; await waiting; }
    await save(...args);
  });
  const heartbeat = vi.spyOn(backend, "heartbeatJob");
  vi.stubGlobal("fetch", vi.fn<typeof fetch>(async () => Response.json({ value: [] })));
  const run = runScanJob(backend, job, "original-worker", config);
  await vi.waitFor(() => expect(pending).toBe(true));
  await vi.advanceTimersByTimeAsync(30000);
  expect(heartbeat).toHaveBeenCalledExactlyOnceWith(job.id, "original-worker");
  expect(Date.parse((await backend.getJob(job.id, tenantId))!.updatedAt)).toBeGreaterThan(Date.parse(job.updatedAt));
  release();
  await run;
  expect(await backend.getJob(job.id, tenantId)).toMatchObject({ status: "complete" });
  expect(await backend.recentSnapshots(tenantId)).toHaveLength(1);
  expect(vi.getTimerCount()).toBe(0);
});

it("refreshes again when a long scan outlives its first renewed token", async () => {
  session.accessTokenExpiresAt = Date.now();
  session.sessionExpiresAt = Date.now() + 3 * 3600000;
  await backend.updateSession(session);
  const job = await claim();
  acquireSilent.mockImplementation(async () => ({
    result: { accessToken: `synthetic-refresh-${acquireSilent.mock.calls.length}`, expiresOn: new Date(Date.now() + 3600000) },
    tokenCache: `synthetic-cache-${acquireSilent.mock.calls.length}`,
  }));
  const fetchImpl = vi.fn<typeof fetch>(async request => {
    const url = new URL(String(request));
    if (url.pathname === "/v1.0/servicePrincipals" && !url.searchParams.has("$expand")) vi.setSystemTime(Date.now() + 56 * 60000);
    return Response.json({ value: [] });
  });
  vi.stubGlobal("fetch", fetchImpl);
  await runScanJob(backend, job, "original-worker", config);
  expect(acquireSilent).toHaveBeenCalledTimes(2);
  expect(acquireSilent).toHaveBeenLastCalledWith(config, session.account, "synthetic-cache-1");
  const lastOptions = fetchImpl.mock.calls.at(-1)![1];
  expect(lastOptions?.headers).toMatchObject({ Authorization: "Bearer synthetic-refresh-2" });
  expect(await backend.getSession(session.id, tenantId)).toMatchObject({ accessToken: "synthetic-refresh-2", tokenCache: "synthetic-cache-2" });
  expect(await backend.getJob(job.id, tenantId)).toMatchObject({ status: "complete" });
});

it("reports a session disappearing between the access check and its lookup without reading Graph", async () => {
  const job = await claim();
  const lookup = backend.getSession.bind(backend);
  vi.spyOn(backend, "getSession").mockImplementation(async (...args) => {
    await backend.deleteSession(session.id, tenantId);
    return lookup(...args);
  });
  const fetchImpl = vi.fn<typeof fetch>();
  vi.stubGlobal("fetch", fetchImpl);
  await runScanJob(backend, job, "original-worker", config);
  expect(fetchImpl).not.toHaveBeenCalled();
  expect(await backend.getJob(job.id, tenantId)).toMatchObject({
    status: "failed", snapshotId: null, error: "The scan session expired or was signed out. Sign in and start a new read-only scan.",
  });
});

it("finishes cancellation before collection even while the original session remains valid", async () => {
  const job = await claim();
  await backend.requestScanCancellation(job.id, tenantId);
  const fetchImpl = vi.fn<typeof fetch>();
  vi.stubGlobal("fetch", fetchImpl);
  await runScanJob(backend, job, "original-worker", config);
  expect(fetchImpl).not.toHaveBeenCalled();
  expect(await backend.getJob(job.id, tenantId)).toMatchObject({ status: "cancelled", snapshotId: null });
  expect(await backend.getSession(session.id, tenantId)).not.toBeNull();
});

it("preserves pending cancellation when its terminal cleanup fails instead of silently retrying a failed write", async () => {
  const job = await claim();
  await backend.requestScanCancellation(job.id, tenantId);
  const cancel = backend.cancelJob.bind(backend);
  const outage = new Error("Synthetic cancellation cleanup failed");
  vi.spyOn(backend, "cancelJob").mockImplementationOnce(async () => { throw outage; }).mockImplementation(cancel);
  await expect(runScanJob(backend, job, "original-worker", config)).rejects.toBe(outage);
  expect(await backend.getJob(job.id, tenantId)).toMatchObject({ status: "cancel_requested", workerId: "original-worker", snapshotId: null });
  expect(await backend.recentSnapshots(tenantId)).toEqual([]);
  expect(vi.getTimerCount()).toBe(0);
});

it("keeps retained evidence from fifteen days ago when publishing a new scan", async () => {
  const previous = await claim();
  const snapshot = { ...structuredClone(cleanProjectFixture), id: randomUUID(), tenant: { ...cleanProjectFixture.tenant, tenantId }, scannedAt: new Date(Date.now() - 15 * 24 * 3600000).toISOString() };
  await backend.completeJob(previous.id, "original-worker", snapshot, new Date(0));
  const job = await claim();
  vi.stubGlobal("fetch", vi.fn<typeof fetch>(async () => Response.json({ value: [] })));
  await runScanJob(backend, job, "original-worker", config);
  const retained = await backend.recentSnapshots(tenantId);
  expect(retained).toHaveLength(2);
  expect(retained.map(value => value.id)).toContain(snapshot.id);
  expect(await backend.getJob(job.id, tenantId)).toMatchObject({ status: "complete" });
});

it("shows the collected stage and count while a checkpoint is pending, then normalizes its evidence", async () => {
  const job = await claim();
  let release!: () => void;
  const waiting = new Promise<void>(resolve => { release = resolve; });
  const save = backend.saveScanCheckpoint.bind(backend);
  vi.spyOn(backend, "saveScanCheckpoint").mockImplementation(async (...args) => {
    if ((args[0].payload as { completedStages: string[] }).completedStages.at(-1) === "usersAndGroups") await waiting;
    await save(...args);
  });
  const progress = vi.spyOn(backend, "updateJobProgress");
  vi.stubGlobal("fetch", vi.fn<typeof fetch>(async request => Response.json({ value: new URL(String(request)).pathname === "/v1.0/users"
    ? [{ id: "person-one", displayName: "Synthetic person one" }, { id: "person-two", displayName: "Synthetic person two" }]
    : [] })));
  const run = runScanJob(backend, job, "original-worker", config);
  await vi.waitFor(async () => expect(await backend.getJob(job.id, tenantId)).toMatchObject({ stage: "usersAndGroups", collected: 2, detail: "People and groups collected" }));
  release();
  await run;
  expect(progress.mock.calls.some(args => args[4].startsWith("Resuming encrypted checkpoint"))).toBe(false);
  expect(progress.mock.calls.find(args => args[2] === "normalizing")?.[4]).toBe("Normalizing source records into explainable relationships");
  expect((await backend.recentSnapshots(tenantId))[0]!.nodes.filter(node => node.kind === "user")).toHaveLength(2);
});

it("refuses a refresh that finishes after the absolute session expiry", async () => {
  session.accessTokenExpiresAt = Date.now();
  await backend.updateSession(session);
  const job = await claim();
  acquireSilent.mockImplementation(async () => {
    vi.setSystemTime(session.sessionExpiresAt);
    return { result: { accessToken: "synthetic-too-late", expiresOn: new Date(Date.now() + 3600000) }, tokenCache: "synthetic-too-late-cache" };
  });
  const fetchImpl = vi.fn<typeof fetch>();
  vi.stubGlobal("fetch", fetchImpl);
  await runScanJob(backend, job, "original-worker", config);
  expect(fetchImpl).not.toHaveBeenCalled();
  expect(await backend.getSession(session.id, tenantId)).toBeNull();
  expect(await backend.getJob(job.id, tenantId)).toMatchObject({ status: "failed", snapshotId: null });
});

it("shares one token refresh across concurrent fan-out reads", async () => {
  session.sessionExpiresAt = Date.now() + 2 * 3600000;
  await backend.updateSession(session);
  const job = await claim();
  let releaseRefresh!: (value: unknown) => void;
  acquireSilent.mockImplementation(async () => new Promise(resolve => { releaseRefresh = resolve; }));
  const fetchImpl = vi.fn<typeof fetch>(async request => {
    const url = new URL(String(request));
    if (url.pathname === "/v1.0/applications") return Response.json({ value: Array.from({ length: 4 }, (_, i) => ({ id: `app-${i}`, appId: `client-${i}`, displayName: `Synthetic ${i}` })) });
    if (url.pathname === "/v1.0/servicePrincipals" && !url.searchParams.has("$expand")) vi.setSystemTime(Date.now() + 56 * 60000);
    return Response.json({ value: [] });
  });
  vi.stubGlobal("fetch", fetchImpl);
  const run = runScanJob(backend, job, "original-worker", config);
  await vi.waitFor(() => expect(acquireSilent).toHaveBeenCalled());
  await vi.advanceTimersByTimeAsync(0);
  expect(acquireSilent).toHaveBeenCalledTimes(1);
  releaseRefresh({ result: { accessToken: "synthetic-shared-refresh", expiresOn: new Date(Date.now() + 3600000) }, tokenCache: "synthetic-shared-cache" });
  await run;
  const childReads = fetchImpl.mock.calls.filter(([url]) => /\/applications\/app-\d\//.test(String(url)));
  expect(childReads).toHaveLength(8);
  for (const [, options] of childReads) expect(options?.headers).toMatchObject({ Authorization: "Bearer synthetic-shared-refresh" });
  expect(await backend.getJob(job.id, tenantId)).toMatchObject({ status: "complete" });
});

it.each([2, 3])("resumes the last committed stage on attempt %i without repeating earlier Graph reads", async attempt => {
  session.sessionExpiresAt = Date.now() + 2 * 3600000;
  await backend.updateSession(session);
  const job = await claim();
  const save = backend.saveScanCheckpoint.bind(backend);
  vi.spyOn(backend, "saveScanCheckpoint").mockImplementation(async (...args) => {
    await save(...args);
    if (args[1] === "original-worker") {
      vi.setSystemTime(Date.now() + 11 * 60000);
      await backend.recoverStaleJobs(tenantId, new Date(Date.now() - 10 * 60000));
      await backend.claimNextJob("replacement-worker", tenantId);
    }
  });
  const progress = vi.spyOn(backend, "updateJobProgress");
  const fetchImpl = vi.fn<typeof fetch>(async () => Response.json({ value: [] }));
  vi.stubGlobal("fetch", fetchImpl);
  await runScanJob(backend, job, "original-worker", config);
  expect((await backend.getScanCheckpoint(job.id, tenantId))?.payload).toMatchObject({ completedStages: ["applications"] });
  let replacement = (await backend.getJob(job.id, tenantId))!;
  expect(replacement).toMatchObject({ workerId: "replacement-worker", attempt: 2 });
  if (attempt === 3) {
    vi.setSystemTime(Date.now() + 11 * 60000);
    await backend.recoverStaleJobs(tenantId, new Date(Date.now() - 10 * 60000));
    replacement = (await backend.claimNextJob("second-replacement-worker", tenantId))!;
  }
  await runScanJob(backend, replacement, replacement.workerId!, config);
  expect(fetchImpl.mock.calls.filter(([url]) => new URL(String(url)).pathname === "/v1.0/applications")).toHaveLength(1);
  expect(progress.mock.calls).toContainEqual([job.id, replacement.workerId, "applications", 0, `Resuming encrypted checkpoint from attempt ${attempt - 1}`]);
  expect(await backend.getJob(job.id, tenantId)).toMatchObject({ status: "complete", attempt });
  expect(await backend.getScanCheckpoint(job.id, tenantId)).toBeNull();
});

it.each([429, 503])("shows retry progress and recovers a transient Graph %s read", async status => {
  const job = await claim();
  const progress = vi.spyOn(backend, "updateJobProgress");
  const fetchImpl = vi.fn<typeof fetch>()
    .mockResolvedValueOnce(new Response(null, { status, headers: { "retry-after": "1" } }))
    .mockImplementation(async () => Response.json({ value: [] }));
  vi.stubGlobal("fetch", fetchImpl);
  const run = runScanJob(backend, job, "original-worker", config);
  await vi.waitFor(() => expect(fetchImpl).toHaveBeenCalledTimes(1));
  await vi.advanceTimersByTimeAsync(1000);
  await run;
  expect(progress.mock.calls).toContainEqual([job.id, "original-worker", "applications", 0, `${status === 429 ? "Microsoft Graph throttled the scan" : "A transient read failed"}; retry 1 in 1 seconds`]);
  expect(fetchImpl).toHaveBeenCalledTimes(9);
  expect(await backend.getJob(job.id, tenantId)).toMatchObject({ status: "complete", completion: "complete" });
});

it("bounds repeated endpoint failures and publishes explicitly partial coverage", async () => {
  session.sessionExpiresAt = Date.now() + 2 * 3600000;
  await backend.updateSession(session);
  const job = await claim();
  const fetchImpl = vi.fn<typeof fetch>(async request => new URL(String(request)).pathname === "/v1.0/applications"
    ? new Response(null, { status: 503, headers: { "retry-after": "1" } })
    : Response.json({ value: [] }));
  vi.stubGlobal("fetch", fetchImpl);
  const run = runScanJob(backend, job, "original-worker", config);
  await vi.advanceTimersByTimeAsync(10000);
  await run;
  expect(fetchImpl.mock.calls.filter(([url]) => new URL(String(url)).pathname === "/v1.0/applications")).toHaveLength(9);
  const snapshot = (await backend.recentSnapshots(tenantId))[0]!;
  expect(snapshot.completion.status).toBe("partial");
  expect(snapshot.completion.errors).toHaveLength(1);
  expect(snapshot.completion.collectors?.find(collector => collector.id === "applications")?.state).toBe("unavailable");
  expect(await backend.getJob(job.id, tenantId)).toMatchObject({ status: "complete", completion: "partial" });
});
