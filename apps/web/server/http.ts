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

/** Route handlers do not inherit the Server Actions request-body limit. */
export async function readJsonObject(request: Request): Promise<Record<string, unknown> | Response> {
  const reader = request.body?.getReader();
  if (!reader) return noStoreJson({ error: "A JSON object is required." }, { status: 400 });
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 131_072) {
        await reader.cancel();
        return noStoreJson({ error: "Request body exceeds 128 KiB." }, { status: 413 });
      }
      chunks.push(value);
    }
    const body: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (body && typeof body === "object" && !Array.isArray(body)) return body as Record<string, unknown>;
  } catch {
    // A broken stream and malformed JSON are both invalid client input.
  } finally {
    reader.releaseLock();
  }
  return noStoreJson({ error: "A JSON object is required." }, { status: 400 });
}
