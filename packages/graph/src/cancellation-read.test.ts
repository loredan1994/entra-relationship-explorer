import { describe, expect, it, vi } from "vitest";
import { ReadOnlyGraphClient } from "./client";
import { ScanCancelledError, scanTenant } from "./scanner";
import { application, jsonResponse, rawScan, sourced, TENANT } from "./test-support";

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(accept => { resolve = accept; });
  return { promise, resolve };
}

describe("cancellation at Graph read boundaries", () => {
  it("stops after the in-flight page without requesting another page or saving a checkpoint", async () => {
    let cancelled = false;
    const checkpoint = vi.fn();
    const fetchImpl = vi.fn<typeof fetch>(async () => {
      cancelled = true;
      return jsonResponse({ value: [], "@odata.nextLink": "https://graph.microsoft.com/v1.0/applications?$skiptoken=next" });
    });
    const client = new ReadOnlyGraphClient("synthetic-token", { fetchImpl, maxPages: 2 });

    await expect(scanTenant(client, TENANT, { shouldCancel: async () => cancelled, onCheckpoint: checkpoint })).rejects.toBeInstanceOf(ScanCancelledError);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(checkpoint).not.toHaveBeenCalled();
  });

  it.each(["throttled", "network"] as const)("interrupts %s backoff within one second without a retry or checkpoint", async failure => {
    let cancelled = false;
    const checkpoint = vi.fn();
    const delays: number[] = [];
    const sleep = vi.fn(async (milliseconds: number) => { delays.push(milliseconds); cancelled = true; });
    const fetchImpl = vi.fn<typeof fetch>(async () => {
      if (failure === "network") throw new TypeError("Synthetic network failure");
      return new Response("", { status: 429, headers: { "retry-after": "300" } });
    });
    const client = new ReadOnlyGraphClient("synthetic-token", { fetchImpl, sleep, maxRetries: 1, random: () => 1 });

    await expect(scanTenant(client, TENANT, { shouldCancel: async () => cancelled, onCheckpoint: checkpoint })).rejects.toBeInstanceOf(ScanCancelledError);
    expect(delays.length).toBeGreaterThan(0);
    expect(delays.reduce((total, delay) => total + delay, 0)).toBeLessThanOrEqual(1_000);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(checkpoint).not.toHaveBeenCalled();
  });

  it("propagates a lease-check failure as the same error instead of recording partial evidence", async () => {
    let requestFinished = false;
    const leaseError = new Error("Synthetic lease was lost");
    const checkpoint = vi.fn();
    const fetchImpl = vi.fn<typeof fetch>(async () => {
      requestFinished = true;
      return jsonResponse({ value: [], "@odata.nextLink": "https://graph.microsoft.com/v1.0/applications?$skiptoken=next" });
    });
    const shouldCancel = async () => { if (requestFinished) throw leaseError; return false; };

    await expect(scanTenant(new ReadOnlyGraphClient("synthetic-token", { fetchImpl, maxPages: 2 }), TENANT, { shouldCancel, onCheckpoint: checkpoint })).rejects.toBe(leaseError);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(checkpoint).not.toHaveBeenCalled();
  });

  it.each(["success", "denied", "network"] as const)("honors cancellation after a terminal %s attempt even with retries disabled", async outcome => {
    let cancelled = false;
    const cancellation = new ScanCancelledError();
    const sleep = vi.fn(async () => {});
    const fetchImpl = vi.fn<typeof fetch>(async () => {
      cancelled = true;
      if (outcome === "network") throw new TypeError("Synthetic network failure");
      return outcome === "denied" ? jsonResponse({ error: { code: "Authorization_RequestDenied" } }, 403) : jsonResponse({ value: [] });
    });
    const client = new ReadOnlyGraphClient("synthetic-token", { fetchImpl, maxRetries: 0, sleep });
    const checkActive = async () => { if (cancelled) throw cancellation; };

    await expect(client.getAll("/applications", undefined, checkActive)).rejects.toBe(cancellation);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(sleep).not.toHaveBeenCalled();
  });

  it.each(["collection", "single object"] as const)("checks cancellation before the first %s request", async kind => {
    const cancellation = new ScanCancelledError();
    const checkActive = async () => { throw cancellation; };
    const fetchImpl = vi.fn<typeof fetch>(async () => jsonResponse({ value: [] }));
    const client = new ReadOnlyGraphClient("synthetic-token", { fetchImpl });
    const read = kind === "collection" ? client.getAll("/applications", undefined, checkActive) : client.getOne("/policies/authorizationPolicy", checkActive);

    await expect(read).rejects.toBe(cancellation);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("does not checkpoint the single-object policy stage when its in-flight read loses the lease", async () => {
    let policyRead = false;
    const leaseError = new Error("Synthetic policy lease was lost");
    const checkpoint = vi.fn();
    const fetchImpl = vi.fn<typeof fetch>(async input => {
      expect(new URL(String(input)).pathname).toBe("/v1.0/policies/authorizationPolicy");
      policyRead = true;
      return jsonResponse({ id: "authorization-policy", displayName: "Synthetic authorization policy" });
    });
    const resumeFrom = rawScan({ completedStages: ["applications", "servicePrincipals", "federatedIdentityCredentials", "usersAndGroups", "groupMemberships", "devices", "administrativeUnits", "delegatedPermissionGrants", "appRoleAssignments", "owners", "roles", "conditionalAccess"] });
    const shouldCancel = async () => { if (policyRead) throw leaseError; return false; };

    await expect(scanTenant(new ReadOnlyGraphClient("synthetic-token", { fetchImpl }), TENANT, {
      resumeFrom, shouldCancel, onCheckpoint: checkpoint, enabledScopes: ["Policy.Read.All"],
    })).rejects.toBe(leaseError);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(checkpoint).not.toHaveBeenCalled();
  });

  it("does not checkpoint the last page when its progress callback requests cancellation", async () => {
    let cancelled = false;
    const checkpoint = vi.fn();
    const fetchImpl = vi.fn<typeof fetch>(async () => jsonResponse({ value: [] }));

    await expect(scanTenant(new ReadOnlyGraphClient("synthetic-token", { fetchImpl }), TENANT, {
      shouldCancel: async () => cancelled,
      onProgress: event => { if (event.stage === "applications") cancelled = true; },
      onCheckpoint: checkpoint,
    })).rejects.toBeInstanceOf(ScanCancelledError);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(checkpoint).not.toHaveBeenCalled();
  });

  it("keeps cancellation latched when a concurrent pending check later returns false", async () => {
    const firstResponse = deferred<Response>();
    const secondResponse = deferred<Response>();
    const lateCheck = deferred<boolean>();
    let phase: "active" | "late" | "cancel" = "active";
    let lateCheckReached = false;
    const checkpoint = vi.fn();
    const requested: string[] = [];
    const fetchImpl = vi.fn<typeof fetch>(async input => {
      const path = new URL(String(input)).pathname;
      requested.push(path);
      if (path === "/v1.0/applications/first/federatedIdentityCredentials") return firstResponse.promise;
      if (path === "/v1.0/applications/second/federatedIdentityCredentials") return secondResponse.promise;
      return jsonResponse({ value: [] });
    });
    const resumeFrom = rawScan({
      applications: ["first", "second", "must-not-start"].map(id => sourced(application({ id, appId: `${id}-app`, displayName: id }))),
      completedStages: ["applications", "servicePrincipals"],
    });
    const shouldCancel = async () => {
      if (phase === "late") { lateCheckReached = true; return lateCheck.promise; }
      return phase === "cancel";
    };
    let outcome: PromiseSettledResult<unknown> | undefined;
    const result = scanTenant(new ReadOnlyGraphClient("synthetic-token", { fetchImpl }), TENANT, { resumeFrom, shouldCancel, onCheckpoint: checkpoint, concurrency: 2 })
      .then(value => { outcome = { status: "fulfilled", value }; }, reason => { outcome = { status: "rejected", reason }; });
    try {
      await vi.waitFor(() => expect(requested).toHaveLength(2));
      phase = "late";
      firstResponse.resolve(jsonResponse({ value: [] }));
      await vi.waitFor(() => expect(lateCheckReached).toBe(true));
      phase = "cancel";
      secondResponse.resolve(jsonResponse({ value: [] }));
      await vi.waitFor(() => expect(outcome).toMatchObject({ status: "rejected", reason: expect.any(ScanCancelledError) }));
      phase = "active";
      lateCheck.resolve(false);
      // Drain the released reader's promise chain before checking that no new read began.
      await new Promise<void>(resolve => setImmediate(resolve));
      expect(requested).toHaveLength(2);
      expect(checkpoint).not.toHaveBeenCalled();
    } finally {
      phase = "active";
      firstResponse.resolve(jsonResponse({ value: [] }));
      secondResponse.resolve(jsonResponse({ value: [] }));
      lateCheck.resolve(false);
      await result;
    }
  });

  it.each(["cancellation", "lease loss"] as const)("sends no Graph request when %s occurs during token refresh", async interruption => {
    const tokenStarted = deferred<void>();
    const token = deferred<string>();
    let interrupted = false;
    const leaseError = new Error("Synthetic lease lost during token refresh");
    const tokenProvider = vi.fn(async () => { tokenStarted.resolve(); return token.promise; });
    const fetchImpl = vi.fn<typeof fetch>(async () => jsonResponse({ value: [] }));
    const sleep = vi.fn(async () => {});
    const retry = vi.fn();
    const checkpoint = vi.fn();
    const shouldCancel = async () => {
      if (interrupted && interruption === "lease loss") throw leaseError;
      return interrupted;
    };
    const read = scanTenant(new ReadOnlyGraphClient(tokenProvider, { fetchImpl, sleep, onRetry: retry }), TENANT, { shouldCancel, onCheckpoint: checkpoint });
    const outcome = read.then(value => ({ status: "fulfilled" as const, value }), reason => ({ status: "rejected" as const, reason }));
    await tokenStarted.promise;
    interrupted = true;
    token.resolve("synthetic-refreshed-token");

    const result = await outcome;
    expect(result.status).toBe("rejected");
    if (result.status === "rejected") {
      if (interruption === "lease loss") expect(result.reason).toBe(leaseError);
      else expect(result.reason).toBeInstanceOf(ScanCancelledError);
    }
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(tokenProvider).toHaveBeenCalledTimes(1);
    expect(sleep).not.toHaveBeenCalled();
    expect(retry).not.toHaveBeenCalled();
    expect(checkpoint).not.toHaveBeenCalled();
  });

  it("retains a one-shot guard rejection through the SDK without retrying it as a network failure", async () => {
    const tokenStarted = deferred<void>();
    const token = deferred<string>();
    const interruption = new Error("Synthetic one-shot interruption");
    let rejectNextCheck = false;
    const checkActive = async () => {
      if (rejectNextCheck) { rejectNextCheck = false; throw interruption; }
    };
    const tokenProvider = vi.fn(async () => { tokenStarted.resolve(); return token.promise; });
    const fetchImpl = vi.fn<typeof fetch>(async () => jsonResponse({ value: [] }));
    const sleep = vi.fn(async () => {});
    const retry = vi.fn();
    const client = new ReadOnlyGraphClient(tokenProvider, { fetchImpl, sleep, onRetry: retry, maxRetries: 1 });
    const result = client.getAll("/applications", undefined, checkActive);
    const rejected = expect(result).rejects.toBe(interruption);
    await tokenStarted.promise;
    rejectNextCheck = true;
    token.resolve("synthetic-refreshed-token");

    await rejected;
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(tokenProvider).toHaveBeenCalledTimes(1);
    expect(sleep).not.toHaveBeenCalled();
    expect(retry).not.toHaveBeenCalled();
  });

  it.each(["cancelled token first", "active token first"] as const)("keeps concurrent read guards separate on a shared client (%s)", async order => {
    const tokens = [deferred<string>(), deferred<string>()];
    const bothStarted = deferred<void>();
    let providersStarted = 0;
    let firstCancelled = false;
    const interruption = new ScanCancelledError();
    const firstGuard = async () => { if (firstCancelled) throw interruption; };
    const secondGuard = vi.fn(async () => {});
    const tokenProvider = vi.fn(async () => {
      const index = providersStarted++;
      if (providersStarted === 2) bothStarted.resolve();
      return tokens[index]!.promise;
    });
    const fetchImpl = vi.fn<typeof fetch>(async () => jsonResponse({ value: [{ id: "still-active" }] }));
    const client = new ReadOnlyGraphClient(tokenProvider, { fetchImpl, maxRetries: 0 });
    const outcomes = Promise.allSettled([
      client.getAll("/applications", undefined, firstGuard),
      client.getAll("/users", undefined, secondGuard),
    ]);
    await bothStarted.promise;
    firstCancelled = true;
    for (const index of order === "cancelled token first" ? [0, 1] : [1, 0]) tokens[index]!.resolve(index === 0 ? "synthetic-cancelled-token" : "synthetic-active-token");

    expect(await outcomes).toEqual([
      { status: "rejected", reason: interruption },
      { status: "fulfilled", value: [{ id: "still-active" }] },
    ]);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(new URL(String(fetchImpl.mock.calls[0]![0])).pathname).toBe("/v1.0/users");
    expect(fetchImpl.mock.calls[0]![1]?.headers).toMatchObject({ Authorization: "Bearer synthetic-active-token" });
    expect(tokenProvider).toHaveBeenCalledTimes(2);
  });
});
