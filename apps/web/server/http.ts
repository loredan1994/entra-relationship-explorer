import "server-only";

export function requireSameOrigin(request: Request, trustedUrl: string): void {
  const origin = request.headers.get("origin");
  const trustedOrigin = new URL(trustedUrl).origin;
  if (!origin || origin !== trustedOrigin) throw new Error("Cross-origin request rejected.");
}

export function noStoreJson(body: unknown, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers);
  headers.set("cache-control", "no-store, private");
  headers.set("content-type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(body), { ...init, headers });
}
