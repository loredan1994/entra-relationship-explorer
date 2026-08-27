import { describe, expect, it, vi } from "vitest";
import { GraphRequestError, ReadOnlyGraphClient, createReadOnlyMiddleware } from "./client";
import { assertReadOnlyScopes, CORE_GRAPH_SCOPES, IDENTITY_SCOPES, OPTIONAL_GRAPH_SCOPES } from "./permissions";
import { jsonResponse } from "./test-support";
import type { Middleware } from "@microsoft/microsoft-graph-client";

function client(fetchImpl: typeof fetch, options = {}) {
  return new ReadOnlyGraphClient("token-value", { fetchImpl, sleep: async () => {}, random: () => 0.5, ...options });
}

describe("access token handling", () => {
  it("reads singleton Graph resources through the same GET-only transport", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse({ id: "authorizationPolicy", displayName: "Authorization policy" }));
    await expect(client(fetchImpl).getOne<{ id: string }>("/policies/authorizationPolicy")).resolves.toEqual({ id: "authorizationPolicy", displayName: "Authorization policy" });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(fetchImpl.mock.calls[0]?.[1]?.method).toBe("GET");
  });

  it("refuses an empty or whitespace-only static token at construction", () => {
    expect(() => new ReadOnlyGraphClient("")).toThrow(/access token is required/);
    expect(() => new ReadOnlyGraphClient("   ")).toThrow(/access token is required/);
  });

  it("resolves a token provider on each request rather than caching it", async () => {
    const provider = vi.fn(async () => "fresh-token");
    // A Response body reads once, so each call must produce a fresh one.
    const fetchImpl = vi.fn<typeof fetch>().mockImplementation(async () => jsonResponse({ value: [] }));
    await client(fetchImpl, {}).getAll("/applications");
    const withProvider = new ReadOnlyGraphClient(provider, { fetchImpl, sleep: async () => {} });
    await withProvider.getAll("/applications");
    await withProvider.getAll("/servicePrincipals");
    expect(provider).toHaveBeenCalledTimes(2);
  });

  it("fails the request when the provider yields a blank token", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse({ value: [] }));
    const withProvider = new ReadOnlyGraphClient(async () => "  ", { fetchImpl, sleep: async () => {}, maxRetries: 0 });
    await expect(withProvider.getAll("/applications")).rejects.toBeInstanceOf(GraphRequestError);
  });

  it("sends the token as a bearer credential with no-store caching", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse({ value: [] }));
    await client(fetchImpl).getAll("/applications");
    const init = fetchImpl.mock.calls[0]![1]!;
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer token-value");
    expect(init.cache).toBe("no-store");
    expect(init.redirect).toBe("error");
  });
});

describe("retry ladder", () => {
  const throttled = () => jsonResponse({ error: { code: "TooManyRequests" } }, 429);

  it("prefers the millisecond retry hint over Retry-After seconds", async () => {
    const sleep = vi.fn<(ms: number) => Promise<void>>().mockResolvedValue(undefined);
    const fetchImpl = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(new Response(JSON.stringify({ error: { code: "TooManyRequests" } }), {
        status: 429, headers: { "content-type": "application/json", "x-ms-retry-after-ms": "1500", "retry-after": "60" },
      }))
      .mockResolvedValueOnce(jsonResponse({ value: [] }));
    await client(fetchImpl, { sleep }).getAll("/applications");
    expect(sleep).toHaveBeenCalledWith(1500);
  });

  it("treats a Retry-After date as a delay, never shorter than a second", async () => {
    const sleep = vi.fn<(ms: number) => Promise<void>>().mockResolvedValue(undefined);
    const past = new Date(Date.now() - 60_000).toUTCString();
    const fetchImpl = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(new Response(JSON.stringify({ error: { code: "TooManyRequests" } }), {
        status: 429, headers: { "content-type": "application/json", "retry-after": past },
      }))
      .mockResolvedValueOnce(jsonResponse({ value: [] }));
    await client(fetchImpl, { sleep }).getAll("/applications");
    expect(sleep).toHaveBeenCalledWith(1_000);
  });

  it("waits until a future Retry-After date", async () => {
    const sleep = vi.fn<(ms: number) => Promise<void>>().mockResolvedValue(undefined);
    const future = new Date(Date.now() + 120_000).toUTCString();
    const fetchImpl = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(new Response(JSON.stringify({ error: { code: "TooManyRequests" } }), {
        status: 429, headers: { "content-type": "application/json", "retry-after": future },
      }))
      .mockResolvedValueOnce(jsonResponse({ value: [] }));
    await client(fetchImpl, { sleep }).getAll("/applications");
    expect(sleep.mock.calls[0]![0]).toBeGreaterThan(100_000);
  });

  it("treats a Retry-After of zero seconds as a one-second wait", async () => {
    const sleep = vi.fn<(ms: number) => Promise<void>>().mockResolvedValue(undefined);
    const fetchImpl = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(new Response(JSON.stringify({ error: { code: "TooManyRequests" } }), {
        status: 429, headers: { "content-type": "application/json", "retry-after": "0" },
      }))
      .mockResolvedValueOnce(jsonResponse({ value: [] }));
    await client(fetchImpl, { sleep }).getAll("/applications");
    expect(sleep).toHaveBeenCalledWith(1_000);
  });

  it("backs off exponentially when the response offers no hint", async () => {
    const sleep = vi.fn<(ms: number) => Promise<void>>().mockResolvedValue(undefined);
    const fetchImpl = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(throttled())
      .mockResolvedValueOnce(throttled())
      .mockResolvedValueOnce(jsonResponse({ value: [] }));
    await client(fetchImpl, { sleep }).getAll("/applications");
    // 2^attempt seconds, jittered by the injected random of 0.5 (factor 1.0).
    expect(sleep.mock.calls.map(([ms]) => ms)).toEqual([1_000, 2_000]);
  });

  it("caps the backoff at the configured ceiling", async () => {
    const sleep = vi.fn<(ms: number) => Promise<void>>().mockResolvedValue(undefined);
    const fetchImpl = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(new Response(JSON.stringify({ error: { code: "TooManyRequests" } }), {
        status: 429, headers: { "content-type": "application/json", "retry-after": "99999" },
      }))
      .mockResolvedValueOnce(jsonResponse({ value: [] }));
    await client(fetchImpl, { sleep, maxRetryDelayMs: 5_000 }).getAll("/applications");
    expect(sleep).toHaveBeenCalledWith(5_000);
  });

  it("reports each retry to the caller with endpoint, status, and delay", async () => {
    const onRetry = vi.fn();
    const fetchImpl = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ error: { code: "ServiceUnavailable" } }, 503))
      .mockResolvedValueOnce(jsonResponse({ value: [] }));
    await client(fetchImpl, { onRetry }).getAll("/applications");
    expect(onRetry).toHaveBeenCalledWith({ endpoint: "/v1.0/applications", status: 503, attempt: 1, delayMs: 1_000 });
  });

  it.each([408, 429, 500, 502, 503, 504])("retries a %i response", async (status) => {
    const fetchImpl = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ error: { code: "Transient" } }, status))
      .mockResolvedValueOnce(jsonResponse({ value: [{ id: "one" }] }));
    await expect(client(fetchImpl).getAll("/applications")).resolves.toEqual([{ id: "one" }]);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it.each([400, 401, 403, 404])("does not retry a %i response", async (status) => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse({ error: { code: "Denied" } }, status));
    await expect(client(fetchImpl).getAll("/applications")).rejects.toMatchObject({ status, code: "Denied" });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("gives up after the configured number of retries", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse({ error: { code: "TooManyRequests" } }, 429));
    await expect(client(fetchImpl, { maxRetries: 2 }).getAll("/applications")).rejects.toMatchObject({ status: 429 });
    expect(fetchImpl).toHaveBeenCalledTimes(3);
  });

  it("reports a network failure as a network error after exhausting retries", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockRejectedValue(new Error("socket closed"));
    await expect(client(fetchImpl, { maxRetries: 1 }).getAll("/applications")).rejects.toMatchObject({ code: "network_error" });
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it("recovers when a transient network failure is followed by a success", async () => {
    const fetchImpl = vi.fn<typeof fetch>()
      .mockRejectedValueOnce(new Error("socket closed"))
      .mockResolvedValueOnce(jsonResponse({ value: [{ id: "one" }] }));
    await expect(client(fetchImpl).getAll("/applications")).resolves.toEqual([{ id: "one" }]);
  });
});

describe("error reporting", () => {
  it("falls back to a generic code when the error body cannot be read", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(new Response("not json", { status: 403 }));
    await expect(client(fetchImpl).getAll("/applications")).rejects.toMatchObject({ code: "request_failed", status: 403 });
  });

  it("falls back to a generic code when the body has no string error code", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse({ error: { code: 42 } }, 403));
    await expect(client(fetchImpl).getAll("/applications")).rejects.toMatchObject({ code: "request_failed" });
  });

  it("never puts the query string or token into the reported endpoint", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse({ error: { code: "Denied" } }, 403));
    await expect(client(fetchImpl).getAll("/applications?$select=id,secret")).rejects.toMatchObject({ endpoint: "/v1.0/applications" });
  });
});

describe("collection bounds", () => {
  const nextLink = (skip: number) => `https://graph.microsoft.com/v1.0/applications?$skiptoken=${skip}`;

  it("rejects a response whose collection is not an array", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse({ value: { id: "one" } }));
    await expect(client(fetchImpl).getAll("/applications")).rejects.toMatchObject({ code: "invalid_collection" });
  });

  it("stops at the page limit rather than following next links forever", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockImplementation(async () => jsonResponse({ value: [{ id: "x" }], "@odata.nextLink": nextLink(1) }));
    await expect(client(fetchImpl, { maxPages: 3 }).getAll("/applications")).rejects.toMatchObject({ code: "page_limit" });
    expect(fetchImpl).toHaveBeenCalledTimes(3);
  });

  it("stops once the item budget is exceeded", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockImplementation(async () => jsonResponse({ value: [{ id: "a" }, { id: "b" }], "@odata.nextLink": nextLink(1) }));
    await expect(client(fetchImpl, { maxItems: 3 }).getAll("/applications")).rejects.toMatchObject({ code: "item_limit" });
  });

  it("reports the running item count to the page callback", async () => {
    const onPage = vi.fn();
    const fetchImpl = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ value: [{ id: "a" }, { id: "b" }], "@odata.nextLink": nextLink(1) }))
      .mockResolvedValueOnce(jsonResponse({ value: [{ id: "c" }] }));
    await client(fetchImpl).getAll("/applications", onPage);
    expect(onPage.mock.calls.map(([count]) => count)).toEqual([2, 3]);
  });

  it("accepts a relative endpoint with or without a leading slash", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockImplementation(async () => jsonResponse({ value: [] }));
    await client(fetchImpl).getAll("/applications");
    await client(fetchImpl).getAll("applications");
    for (const call of fetchImpl.mock.calls) {
      expect(String(call[0] instanceof Request ? call[0].url : call[0])).toBe("https://graph.microsoft.com/v1.0/applications");
    }
  });

  it("rejects a plain-HTTP next link", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse({ value: [], "@odata.nextLink": "http://graph.microsoft.com/v1.0/applications" }));
    await expect(client(fetchImpl).getAll("/applications")).rejects.toMatchObject({ code: "invalid_next_link" });
  });
});

describe("approved permission set", () => {
  it("requires at least one scope", () => {
    expect(() => assertReadOnlyScopes([])).toThrow(/At least one scope/);
  });

  it("accepts every documented identity, core, and optional scope", () => {
    expect(() => assertReadOnlyScopes([...IDENTITY_SCOPES, ...CORE_GRAPH_SCOPES, ...OPTIONAL_GRAPH_SCOPES])).not.toThrow();
  });

  it("rejects a scope outside the approved set before checking for write capability", () => {
    expect(() => assertReadOnlyScopes(["https://graph.microsoft.com/Files.Read.All"])).toThrow(/outside the approved read-only set/);
  });

  it("names the offending scope so the failure is actionable", () => {
    expect(() => assertReadOnlyScopes(["Mail.Read"])).toThrow(/Mail\.Read/);
  });

  it("rejects a write-capable scope even alongside approved ones", () => {
    expect(() => assertReadOnlyScopes([...CORE_GRAPH_SCOPES, "https://graph.microsoft.com/Directory.ReadWrite.All"])).toThrow(/outside|write/i);
  });

  it("exposes no write-capable scope in the approved lists", () => {
    for (const scope of [...CORE_GRAPH_SCOPES, ...OPTIONAL_GRAPH_SCOPES]) {
      expect(scope, scope).not.toMatch(/readwrite|\.write\b/i);
    }
  });
});

describe("read-only middleware", () => {
  function context(request: string, options?: RequestInit) {
    return { request, options, middlewareControl: undefined } as unknown as Parameters<Middleware["execute"]>[0] & { response?: Response };
  }

  it("rejects any method other than GET before a token is resolved", async () => {
    const accessToken = vi.fn(async () => "token-value");
    const fetchImpl = vi.fn<typeof fetch>();
    const middleware = createReadOnlyMiddleware({ accessToken, fetchImpl, requestTimeoutMs: 1_000 });
    for (const method of ["POST", "PATCH", "PUT", "DELETE", "post"]) {
      await expect(
        middleware.execute(context("https://graph.microsoft.com/v1.0/applications", { method })),
      ).rejects.toMatchObject({ code: "write_method_rejected", status: 0, endpoint: "/v1.0/applications" });
    }
    expect(accessToken).not.toHaveBeenCalled();
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("treats a request that carries no method as the GET it defaults to", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse({ value: [] }));
    const middleware = createReadOnlyMiddleware({ accessToken: "token-value", fetchImpl, requestTimeoutMs: 1_000 });
    const ctx = context("https://graph.microsoft.com/v1.0/applications");
    await middleware.execute(ctx);
    expect(fetchImpl.mock.calls[0]![1]!.method).toBe("GET");
    expect(ctx.response).toBeInstanceOf(Response);
  });

  it("forces GET even when the caller asked for a lowercase get", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse({ value: [] }));
    const middleware = createReadOnlyMiddleware({ accessToken: "token-value", fetchImpl, requestTimeoutMs: 1_000 });
    await expect(
      middleware.execute(context("https://graph.microsoft.com/v1.0/applications", { method: "get" })),
    ).rejects.toMatchObject({ code: "write_method_rejected" });
  });

  it("refuses to send a request when the provider yields a blank token", async () => {
    const fetchImpl = vi.fn<typeof fetch>();
    const middleware = createReadOnlyMiddleware({ accessToken: async () => "   ", fetchImpl, requestTimeoutMs: 1_000 });
    await expect(middleware.execute(context("https://graph.microsoft.com/v1.0/applications", { method: "GET" })))
      .rejects.toThrow(/token_unavailable/);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("aborts a request that outlives the configured timeout", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse({ value: [] }));
    const middleware = createReadOnlyMiddleware({ accessToken: "token-value", fetchImpl, requestTimeoutMs: 5 });
    await middleware.execute(context("https://graph.microsoft.com/v1.0/applications", { method: "GET" }));
    const signal = fetchImpl.mock.calls[0]![1]!.signal!;
    expect(signal.aborted).toBe(false);
    await new Promise((resolve) => setTimeout(resolve, 25));
    expect(signal.aborted).toBe(true);
  });
});

describe("client defaults", () => {
  it("uses the ambient fetch when the caller supplies none", async () => {
    const ambient = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse({ value: [{ id: "app-1" }] }));
    vi.stubGlobal("fetch", ambient);
    try {
      const items = await new ReadOnlyGraphClient("token-value").getAll<{ id: string }>("/applications");
      expect(items).toEqual([{ id: "app-1" }]);
      expect(ambient).toHaveBeenCalledTimes(1);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("actually waits for the hinted delay when the caller supplies no sleep", async () => {
    const ambient = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(new Response(JSON.stringify({ error: { code: "TooManyRequests" } }), {
        status: 429, headers: { "content-type": "application/json", "x-ms-retry-after-ms": "40" },
      }))
      .mockResolvedValueOnce(jsonResponse({ value: [] }));
    vi.stubGlobal("fetch", ambient);
    const startedAt = performance.now();
    try {
      await new ReadOnlyGraphClient("token-value").getAll("/applications");
      expect(performance.now() - startedAt).toBeGreaterThanOrEqual(30);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("waits with real time when the caller supplies no sleep", async () => {
    const ambient = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(new Response(JSON.stringify({ error: { code: "TooManyRequests" } }), {
        status: 429, headers: { "content-type": "application/json", "x-ms-retry-after-ms": "1" },
      }))
      .mockResolvedValueOnce(jsonResponse({ value: [] }));
    vi.stubGlobal("fetch", ambient);
    try {
      await expect(new ReadOnlyGraphClient("token-value").getAll("/applications")).resolves.toEqual([]);
      expect(ambient).toHaveBeenCalledTimes(2);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("jitters the exponential delay with Math.random when no generator is supplied", async () => {
    const sleep = vi.fn<(ms: number) => Promise<void>>().mockResolvedValue(undefined);
    const fetchImpl = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ error: { code: "TooManyRequests" } }, 429))
      .mockResolvedValueOnce(jsonResponse({ value: [] }));
    const random = vi.spyOn(Math, "random").mockReturnValue(0);
    try {
      await new ReadOnlyGraphClient("token-value", { fetchImpl, sleep }).getAll("/applications");
      expect(random).toHaveBeenCalled();
      // attempt 0: 1000ms exponential x (0.8 + 0 x 0.4).
      expect(sleep).toHaveBeenCalledWith(800);
    } finally {
      random.mockRestore();
    }
  });

  it("reports retry exhaustion when the retry budget leaves no attempt to make", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse({ value: [] }));
    await expect(client(fetchImpl, { maxRetries: -1 }).getAll("/applications"))
      .rejects.toMatchObject({ code: "retry_exhausted", status: 0, endpoint: "/v1.0/applications" });
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});

describe("retry hint boundaries", () => {
  const throttledWith = (headers: Record<string, string>) =>
    new Response(JSON.stringify({ error: { code: "TooManyRequests" } }), {
      status: 429, headers: { "content-type": "application/json", ...headers },
    });

  function retryOnce(headers: Record<string, string>) {
    const sleep = vi.fn<(ms: number) => Promise<void>>().mockResolvedValue(undefined);
    const fetchImpl = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(throttledWith(headers))
      .mockResolvedValueOnce(jsonResponse({ value: [] }));
    return { sleep, run: () => client(fetchImpl, { sleep }).getAll("/applications") };
  }

  it("honours a millisecond hint of zero rather than falling through to the next hint", async () => {
    const { sleep, run } = retryOnce({ "x-ms-retry-after-ms": "0", "retry-after": "60" });
    await run();
    expect(sleep).toHaveBeenCalledWith(0);
  });

  it("ignores a negative millisecond hint and uses the Retry-After seconds instead", async () => {
    const { sleep, run } = retryOnce({ "x-ms-retry-after-ms": "-5", "retry-after": "3" });
    await run();
    expect(sleep).toHaveBeenCalledWith(3_000);
  });

  it("falls back to Retry-After seconds when no millisecond hint is present", async () => {
    const { sleep, run } = retryOnce({ "retry-after": "3" });
    await run();
    expect(sleep).toHaveBeenCalledWith(3_000);
  });

  it("ignores a Retry-After that is neither a number nor a date", async () => {
    const { sleep, run } = retryOnce({ "retry-after": "soon" });
    await run();
    // Falls through to the jittered exponential ladder: 1000ms x (0.8 + 0.5 x 0.4).
    expect(sleep).toHaveBeenCalledWith(1_000);
  });

  it("keeps a response with no headers at all on the exponential ladder", async () => {
    const { sleep, run } = retryOnce({});
    await run();
    expect(sleep).toHaveBeenCalledWith(1_000);
  });
});

describe("request and response bounds", () => {
  it("accepts a page that lands exactly on the item ceiling", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse({ value: [{ id: "a" }, { id: "b" }] }));
    await expect(client(fetchImpl, { maxItems: 2 }).getAll("/applications")).resolves.toHaveLength(2);
  });

  it("refuses the page that takes the collection past the item ceiling", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse({ value: [{ id: "a" }, { id: "b" }, { id: "c" }] }));
    await expect(client(fetchImpl, { maxItems: 2 }).getAll("/applications")).rejects.toMatchObject({ code: "item_limit" });
  });

  it("asks Microsoft Graph for JSON explicitly", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse({ value: [] }));
    await client(fetchImpl).getAll("/applications");
    expect((fetchImpl.mock.calls[0]![1]!.headers as Record<string, string>).Accept).toBe("application/json");
  });

  it("keeps every segment of a nested relative endpoint", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse({ value: [] }));
    await client(fetchImpl).getAll("applications/app-1/owners");
    expect(String(fetchImpl.mock.calls[0]![0])).toBe("https://graph.microsoft.com/v1.0/applications/app-1/owners");
  });

  it("treats an endpoint whose query text ends in http as relative, not absolute", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse({ value: [] }));
    await client(fetchImpl).getAll("/applications?$search=http");
    expect(String(fetchImpl.mock.calls[0]![0])).toContain("https://graph.microsoft.com/v1.0/applications");
  });

  it("refuses a next link that points at another host over HTTPS", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(
      jsonResponse({ value: [], "@odata.nextLink": "https://graph.microsoft.com.evil.example/v1.0/applications" }),
    );
    await expect(client(fetchImpl).getAll("/applications")).rejects.toMatchObject({ code: "invalid_next_link" });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });
});
