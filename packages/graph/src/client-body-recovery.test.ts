import { describe, expect, it, vi } from "vitest";
import { GraphRequestError, ReadOnlyGraphClient } from "./client";
import { ScanCancelledError, scanTenant } from "./scanner";

const TENANT = "11111111-1111-4111-8111-111111111111";

function brokenBody(reason: unknown, onRead?: () => void): Response {
  return new Response(new ReadableStream({
    pull(controller) { onRead?.(); controller.error(reason); },
  }, { highWaterMark: 0 }), { status: 200 });
}

describe("recovery after successful Graph headers", () => {
  it.each([
    ["connection termination", () => new TypeError("terminated")],
    ["body timeout", () => new DOMException("Timed out", "TimeoutError")],
    ["body abort", () => new DOMException("Aborted", "AbortError")],
  ] as const)("retries a %s while reading the body with a fresh token and GET only", async (_name, error) => {
    const tokenProvider = vi.fn().mockResolvedValueOnce("synthetic-first").mockResolvedValueOnce("synthetic-refreshed");
    const fetchImpl = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(brokenBody(error()))
      .mockResolvedValueOnce(Response.json({ id: "policy", displayName: "Recovered policy" }));
    const sleep = vi.fn(async () => {});
    const onRetry = vi.fn();
    const client = new ReadOnlyGraphClient(tokenProvider, { fetchImpl, sleep, onRetry, random: () => 0.5 });

    await expect(client.getOne("/policies/authorizationPolicy")).resolves.toEqual({ id: "policy", displayName: "Recovered policy" });
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(tokenProvider).toHaveBeenCalledTimes(2);
    expect(sleep).toHaveBeenCalledWith(1_000);
    expect(onRetry).toHaveBeenCalledWith({ endpoint: "/v1.0/policies/authorizationPolicy", status: 0, attempt: 1, delayMs: 1_000 });
    for (const [, options] of fetchImpl.mock.calls) {
      expect(options).toMatchObject({ method: "GET", cache: "no-store", redirect: "error" });
      expect(options?.body).toBeUndefined();
    }
    expect(fetchImpl.mock.calls[1]![1]?.headers).toMatchObject({ Authorization: "Bearer synthetic-refreshed" });
  });

  it("retries only the failed page without duplicating earlier records or progress", async () => {
    const next = "https://graph.microsoft.com/v1.0/applications?$skiptoken=synthetic-next";
    const fetchImpl = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(Response.json({ value: [{ id: "first" }], "@odata.nextLink": next }))
      .mockResolvedValueOnce(brokenBody(new TypeError("terminated")))
      .mockResolvedValueOnce(Response.json({ value: [{ id: "second" }] }));
    const onPage = vi.fn();
    const client = new ReadOnlyGraphClient("synthetic-token", { fetchImpl, sleep: async () => {} });

    await expect(client.getAll("/applications", onPage)).resolves.toEqual([{ id: "first" }, { id: "second" }]);
    expect(fetchImpl.mock.calls.map(([url]) => String(url))).toEqual(["https://graph.microsoft.com/v1.0/applications", next, next]);
    expect(onPage.mock.calls).toEqual([[1], [2]]);
  });

  it("bounds repeated body failures and returns a sanitized transport error", async () => {
    const fetchImpl = vi.fn<typeof fetch>(async () => brokenBody(new TypeError("synthetic-private-response")));
    const sleep = vi.fn(async () => {});
    const client = new ReadOnlyGraphClient("synthetic-secret-token", { fetchImpl, sleep, maxRetries: 2, random: () => 0.5 });

    const error = await client.getAll("/applications").catch((reason: unknown) => reason);
    expect(error).toBeInstanceOf(GraphRequestError);
    expect(error).toMatchObject({ status: 0, code: "network_error", endpoint: "/v1.0/applications" });
    expect(String(error)).not.toMatch(/synthetic-private-response|synthetic-secret-token/);
    expect(fetchImpl).toHaveBeenCalledTimes(3);
    expect(sleep.mock.calls).toEqual([[1_000], [2_000]]);
  });

  it("reports invalid JSON without retrying it or exposing the response", async () => {
    const fetchImpl = vi.fn<typeof fetch>(async () => new Response("synthetic-private-invalid-json", { status: 200 }));
    const sleep = vi.fn(async () => {});
    const client = new ReadOnlyGraphClient("synthetic-token", { fetchImpl, sleep, maxRetries: 2 });

    const error = await client.getAll("/applications").catch((reason: unknown) => reason);
    expect(error).toBeInstanceOf(GraphRequestError);
    expect(error).toMatchObject({ status: 0, code: "invalid_json", endpoint: "/v1.0/applications" });
    expect(String(error)).not.toContain("synthetic-private-invalid-json");
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(sleep).not.toHaveBeenCalled();
  });

  it.each(["cancellation", "lease loss"] as const)("preserves %s during a failed body read without retrying or checkpointing", async mode => {
    let interrupted = false;
    const leaseError = new Error("Synthetic lease lost");
    const shouldCancel = async () => {
      if (interrupted && mode === "lease loss") throw leaseError;
      return interrupted;
    };
    const fetchImpl = vi.fn<typeof fetch>(async () => brokenBody(new TypeError("terminated"), () => { interrupted = true; }));
    const sleep = vi.fn(async () => {});
    const onRetry = vi.fn();
    const onCheckpoint = vi.fn();
    const read = scanTenant(new ReadOnlyGraphClient("synthetic-token", { fetchImpl, sleep, onRetry }), TENANT, { shouldCancel, onCheckpoint });

    if (mode === "lease loss") await expect(read).rejects.toBe(leaseError);
    else await expect(read).rejects.toBeInstanceOf(ScanCancelledError);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(sleep).not.toHaveBeenCalled();
    expect(onRetry).not.toHaveBeenCalled();
    expect(onCheckpoint).not.toHaveBeenCalled();
  });

  it("checks cancellation during body-failure backoff before sending another request", async () => {
    const interruption = new ScanCancelledError();
    let cancelled = false;
    const checkActive = async () => { if (cancelled) throw interruption; };
    const fetchImpl = vi.fn<typeof fetch>(async () => brokenBody(new TypeError("terminated")));
    const sleep = vi.fn(async () => { cancelled = true; });
    const client = new ReadOnlyGraphClient("synthetic-token", { fetchImpl, sleep, random: () => 0.5 });

    await expect(client.getAll("/applications", undefined, checkActive)).rejects.toBe(interruption);
    expect(sleep).toHaveBeenCalledExactlyOnceWith(1_000);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it.each(["headers", "body"] as const)("does not misclassify a one-shot guard rejection after %s as a network failure", async phase => {
    const interruption = new SyntaxError("Synthetic caller interruption");
    let rejectNextCheck = false;
    const checkActive = async () => {
      if (rejectNextCheck) { rejectNextCheck = false; throw interruption; }
    };
    const fetchImpl = vi.fn<typeof fetch>(async () => {
      if (phase === "headers") { rejectNextCheck = true; return Response.json({ value: [] }); }
      return new Response(new ReadableStream({
        pull(controller) {
          rejectNextCheck = true;
          controller.enqueue(new TextEncoder().encode('{"value":[]}'));
          controller.close();
        },
      }, { highWaterMark: 0 }));
    });
    const sleep = vi.fn(async () => {});
    const onRetry = vi.fn();
    const client = new ReadOnlyGraphClient("synthetic-token", { fetchImpl, sleep, onRetry });

    await expect(client.getAll("/applications", undefined, checkActive)).rejects.toBe(interruption);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(sleep).not.toHaveBeenCalled();
    expect(onRetry).not.toHaveBeenCalled();
  });
});
