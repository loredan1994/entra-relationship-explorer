import { describe, expect, it } from "vitest";
import { noStoreJson, readJsonObject, requireSameOrigin } from "./http";

const TRUSTED = "https://explorer.contoso.test/api/auth/callback";

function requestFrom(origin: string | null): Request {
  return new Request("https://explorer.contoso.test/api/scan", {
    method: "POST",
    headers: origin === null ? {} : { origin },
  });
}

describe("same-origin enforcement", () => {
  it("accepts a request whose origin matches the configured redirect origin", () => {
    expect(() => requireSameOrigin(requestFrom("https://explorer.contoso.test"), TRUSTED)).not.toThrow();
  });

  it("rejects a request carrying no Origin header at all", () => {
    // A missing Origin is not treated as same-origin: state-changing routes must be
    // reached from the app itself, and a form post from another site omits it.
    expect(() => requireSameOrigin(requestFrom(null), TRUSTED)).toThrow(/Cross-origin request rejected/);
  });

  it("rejects a different host, scheme, or port even when the host name is a prefix", () => {
    for (const origin of [
      "https://evil.test",
      "http://explorer.contoso.test",
      "https://explorer.contoso.test:8443",
      "https://explorer.contoso.test.evil.test",
      "null",
      "",
    ]) {
      expect(() => requireSameOrigin(requestFrom(origin), TRUSTED), origin).toThrow(/Cross-origin request rejected/);
    }
  });

  it("compares against the origin of the trusted URL, ignoring its path", () => {
    expect(() => requireSameOrigin(requestFrom("https://explorer.contoso.test"), "https://explorer.contoso.test/some/other/path?x=1")).not.toThrow();
  });

  it("accepts a loopback development origin when that is what is configured", () => {
    expect(() => requireSameOrigin(requestFrom("http://127.0.0.1:3000"), "http://127.0.0.1:3000/api/auth/callback")).not.toThrow();
    expect(() => requireSameOrigin(requestFrom("http://localhost:3000"), "http://127.0.0.1:3000/api/auth/callback")).toThrow();
  });
});

describe("bounded route JSON", () => {
  function post(body: BodyInit | null, headers?: HeadersInit): Request {
    return new Request("https://explorer.contoso.test/api/reviews", { method: "PUT", body, headers, duplex: "half" } as RequestInit);
  }

  it("accepts the exact byte boundary and preserves Unicode across chunk boundaries", async () => {
    const json = JSON.stringify({ rationale: "é".repeat(65_528) });
    expect(Buffer.byteLength(json)).toBe(131_072);
    const bytes = new TextEncoder().encode(json);
    const body = new ReadableStream({ start(controller) {
      controller.enqueue(bytes.slice(0, 15));
      controller.enqueue(bytes.slice(15));
      controller.close();
    } });
    expect(await readJsonObject(post(body))).toEqual(JSON.parse(json));
  });

  it("rejects actual oversized bytes regardless of missing or misleading length", async () => {
    for (const headers of [undefined, { "content-length": "1" }]) {
      const result = await readJsonObject(post(JSON.stringify({ value: "x".repeat(131_061) }), headers));
      expect(result).toBeInstanceOf(Response);
      expect((result as Response).status).toBe(413);
      expect((result as Response).headers.get("cache-control")).toBe("no-store, private");
      expect(await (result as Response).json()).toEqual({ error: "Request body exceeds 128 KiB." });
    }
  });

  it("cancels an overflowing stream without consuming the rest", async () => {
    let reads = 0;
    let cancelled = false;
    const body = new ReadableStream({ pull(controller) {
      reads++;
      controller.enqueue(new Uint8Array(65_537));
    }, cancel() { cancelled = true; } }, { highWaterMark: 0 });
    expect((await readJsonObject(post(body)) as Response).status).toBe(413);
    expect(reads).toBe(2);
    expect(cancelled).toBe(true);
    expect(body.locked).toBe(false);
  });

  it.each([null, "", "{", "null", "[]", "true", "1", '"text"'])("rejects malformed or non-object input %s", async body => {
    const result = await readJsonObject(post(body));
    expect((result as Response).status).toBe(400);
    expect(await (result as Response).json()).toEqual({ error: "A JSON object is required." });
  });

  it("turns stream failure into a client error and releases the lock", async () => {
    const body = new ReadableStream({ pull(controller) { controller.error(new Error("connection lost")); } });
    expect((await readJsonObject(post(body)) as Response).status).toBe(400);
    expect(body.locked).toBe(false);
  });
});

describe("no-store JSON responses", () => {
  it("marks every response private and uncacheable", async () => {
    const response = noStoreJson({ ok: true });
    expect(response.headers.get("cache-control")).toBe("no-store, private");
    expect(response.headers.get("content-type")).toBe("application/json; charset=utf-8");
    expect(await response.json()).toEqual({ ok: true });
    expect(response.status).toBe(200);
  });

  it("keeps the caller's status and extra headers", () => {
    const response = noStoreJson({ error: "nope" }, { status: 401, headers: { "x-request-id": "abc" } });
    expect(response.status).toBe(401);
    expect(response.headers.get("x-request-id")).toBe("abc");
  });

  it("overrides a caller-supplied cache directive rather than trusting it", () => {
    // Tenant data must never be cached, even if a route hands in its own headers.
    const response = noStoreJson({}, { headers: { "cache-control": "public, max-age=3600", "content-type": "text/html" } });
    expect(response.headers.get("cache-control")).toBe("no-store, private");
    expect(response.headers.get("content-type")).toBe("application/json; charset=utf-8");
  });

  it("serializes the body as JSON", async () => {
    expect(await noStoreJson([1, "two", null]).json()).toEqual([1, "two", null]);
  });
});
