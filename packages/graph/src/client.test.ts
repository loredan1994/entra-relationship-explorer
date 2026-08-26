import { describe, expect, it, vi } from "vitest";
import { GraphRequestError, ReadOnlyGraphClient } from "./client";

describe("ReadOnlyGraphClient", () => {
  it("follows Microsoft Graph next links using GET only", async () => {
    const fetchImpl = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(new Response(JSON.stringify({
        value: [{ id: "one" }],
        "@odata.nextLink": "https://graph.microsoft.com/v1.0/applications?$skiptoken=next",
      }), { status: 200, headers: { "content-type": "application/json" } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ value: [{ id: "two" }] }), {
        status: 200, headers: { "content-type": "application/json" },
      }));
    const client = new ReadOnlyGraphClient("token-value", { fetchImpl });

    await expect(client.getAll<{ id: string }>("/applications")).resolves.toEqual([{ id: "one" }, { id: "two" }]);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    for (const call of fetchImpl.mock.calls) {
      expect(call[1]?.method).toBe("GET");
      expect(call[1]?.body).toBeUndefined();
    }
  });

  it("rejects a next link outside Microsoft Graph", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify({
      value: [], "@odata.nextLink": "https://attacker.example/collect",
    }), { status: 200, headers: { "content-type": "application/json" } }));
    const client = new ReadOnlyGraphClient("token-value", { fetchImpl });
    await expect(client.getAll("/applications")).rejects.toMatchObject({ code: "invalid_next_link" });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("rejects a next link for an unapproved Microsoft Graph API version", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify({
      value: [], "@odata.nextLink": "https://graph.microsoft.com/beta/applications?$skiptoken=next",
    }), { status: 200, headers: { "content-type": "application/json" } }));
    await expect(new ReadOnlyGraphClient("token-value", { fetchImpl }).getAll("/applications")).rejects.toMatchObject({ code: "invalid_next_link" });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("honors Retry-After for throttled reads", async () => {
    const sleep = vi.fn<(milliseconds: number) => Promise<void>>().mockResolvedValue(undefined);
    const fetchImpl = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(new Response(JSON.stringify({ error: { code: "TooManyRequests" } }), {
        status: 429, headers: { "content-type": "application/json", "retry-after": "2" },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ value: [] }), {
        status: 200, headers: { "content-type": "application/json" },
      }));
    const client = new ReadOnlyGraphClient("token-value", { fetchImpl, sleep });
    await client.getAll("/applications");
    expect(sleep).toHaveBeenCalledWith(2_000);
  });

  it("honors millisecond retry guidance and reports the wait", async () => {
    const sleep = vi.fn<(milliseconds: number) => Promise<void>>().mockResolvedValue(undefined);
    const onRetry = vi.fn();
    const fetchImpl = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(new Response("", { status: 503, headers: { "x-ms-retry-after-ms": "1250" } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ value: [] }), { status: 200, headers: { "content-type": "application/json" } }));
    await new ReadOnlyGraphClient("token", { fetchImpl, sleep, onRetry }).getAll("/applications");
    expect(sleep).toHaveBeenCalledWith(1_250);
    expect(onRetry).toHaveBeenCalledWith(expect.objectContaining({ status: 503, attempt: 1, delayMs: 1_250 }));
  });

  it("retries transient network failures and refreshes the token provider per page", async () => {
    const sleep = vi.fn<(milliseconds: number) => Promise<void>>().mockResolvedValue(undefined);
    const tokenProvider = vi.fn().mockResolvedValueOnce("first-token").mockResolvedValueOnce("second-token");
    const fetchImpl = vi.fn<typeof fetch>()
      .mockRejectedValueOnce(new TypeError("network unavailable"))
      .mockResolvedValueOnce(new Response(JSON.stringify({ value: [] }), { status: 200, headers: { "content-type": "application/json" } }));
    await new ReadOnlyGraphClient(tokenProvider, { fetchImpl, sleep, random: () => 0.5 }).getAll("/applications");
    expect(tokenProvider).toHaveBeenCalledTimes(2);
    expect(sleep).toHaveBeenCalledWith(1_000);
  });

  it("never includes the bearer token in an error", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(new Response("not json", { status: 403 }));
    const client = new ReadOnlyGraphClient("highly-sensitive-token", { fetchImpl, maxRetries: 0 });
    const error = await client.getAll("/applications").catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(GraphRequestError);
    expect(String(error)).not.toContain("highly-sensitive-token");
  });

  it("stops after the configured retry bound and caps backoff", async () => {
    const sleep = vi.fn<(milliseconds: number) => Promise<void>>().mockResolvedValue(undefined);
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(new Response("", { status: 503, headers: { "x-ms-retry-after-ms": "999999" } }));
    await expect(new ReadOnlyGraphClient("token", { fetchImpl, sleep, maxRetries: 2, maxRetryDelayMs: 2_500 }).getAll("/applications")).rejects.toMatchObject({ status: 503 });
    expect(fetchImpl).toHaveBeenCalledTimes(3);
    expect(sleep).toHaveBeenCalledTimes(2);
    expect(sleep).toHaveBeenNthCalledWith(1, 2_500);
    expect(sleep).toHaveBeenNthCalledWith(2, 2_500);
  });
});
