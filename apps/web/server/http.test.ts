import { describe, expect, it } from "vitest";
import { noStoreJson, requireSameOrigin } from "./http";

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
