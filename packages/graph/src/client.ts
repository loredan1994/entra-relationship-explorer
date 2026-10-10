const GRAPH_ORIGIN = "https://graph.microsoft.com";
const GRAPH_ROOT = `${GRAPH_ORIGIN}/v1.0/`;

interface GraphPage<T> {
  value: T[];
  "@odata.nextLink"?: unknown;
}

export interface ReadOnlyGraphClientOptions {
  fetchImpl?: typeof fetch;
  sleep?: (milliseconds: number) => Promise<void>;
  maxRetries?: number;
  maxPages?: number;
  maxItems?: number;
  maxRetryDelayMs?: number;
  requestTimeoutMs?: number;
  random?: () => number;
  onRetry?: (event: { endpoint: string; status: number; attempt: number; delayMs: number }) => void;
}

export type AccessTokenProvider = string | (() => Promise<string>);
/** Rejects when the caller no longer owns or wants this read; never retried as a transport failure. */
export type GraphReadGuard = () => Promise<void>;

/** SDK middleware options are scoped to one request, including its token refresh. */
class ReadGuardOptions {
  interruption?: { reason: unknown };
  constructor(private readonly checkActive?: GraphReadGuard) {}

  async verify(): Promise<void> {
    try { await this.checkActive?.(); }
    catch (reason) { this.interruption = { reason }; throw reason; }
  }
}

export class GraphRequestError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly endpoint: string,
  ) {
    super(`Microsoft Graph read failed for ${endpoint} (${status}, ${code}).`);
    this.name = "GraphRequestError";
  }
}

export class ReadOnlyGraphClient {
  private readonly fetchImpl: typeof fetch;
  private readonly sleep: (milliseconds: number) => Promise<void>;
  private readonly maxRetries: number;
  private readonly maxPages: number;
  private readonly maxItems: number;
  private readonly maxRetryDelayMs: number;
  private readonly requestTimeoutMs: number;
  private readonly random: () => number;
  private readonly onRetry?: ReadOnlyGraphClientOptions["onRetry"];
  private readonly sdkClient: Client;

  constructor(
    private readonly accessToken: AccessTokenProvider,
    options: ReadOnlyGraphClientOptions = {},
  ) {
    if (typeof accessToken === "string" && !accessToken.trim()) throw new Error("A Microsoft Graph access token is required.");
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.sleep = options.sleep ?? ((milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)));
    this.maxRetries = options.maxRetries ?? 5;
    this.maxPages = options.maxPages ?? 10_000;
    this.maxItems = options.maxItems ?? 1_000_000;
    this.maxRetryDelayMs = options.maxRetryDelayMs ?? 5 * 60 * 1_000;
    this.requestTimeoutMs = options.requestTimeoutMs ?? 30_000;
    this.random = options.random ?? Math.random;
    this.onRetry = options.onRetry;
    this.sdkClient = Client.initWithMiddleware({
      baseUrl: GRAPH_ORIGIN,
      // Stryker disable next-line StringLiteral: every request is issued with an absolute, validated URL, so the SDK never applies this default.
      defaultVersion: "v1.0",
      middleware: createReadOnlyMiddleware({ accessToken, fetchImpl: this.fetchImpl, requestTimeoutMs: this.requestTimeoutMs }),
    });
  }

  get collectionLimits(): { maxPagesPerEndpoint: number; maxItemsPerEndpoint: number } {
    return { maxPagesPerEndpoint: this.maxPages, maxItemsPerEndpoint: this.maxItems };
  }

  async getAll<T>(endpoint: string, onPage?: (totalItems: number) => void, checkActive?: GraphReadGuard): Promise<T[]> {
    let nextUrl: string | undefined = this.resolveGraphUrl(endpoint);
    const items: T[] = [];
    let pages = 0;

    while (nextUrl) {
      if (++pages > this.maxPages) throw new GraphRequestError(0, "page_limit", endpoint);
      const page: GraphPage<T> = await this.getPage<T>(nextUrl, checkActive);
      if (!Array.isArray(page?.value)) throw new GraphRequestError(0, "invalid_collection", endpoint);
      if (items.length + page.value.length > this.maxItems) throw new GraphRequestError(0, "item_limit", endpoint);
      const nextLink = page["@odata.nextLink"];
      // Only an absent continuation establishes that the collection ended. Treating
      // a malformed falsey value as the last page would incorrectly certify coverage.
      if (nextLink !== undefined && (typeof nextLink !== "string" || !nextLink.trim())) throw new GraphRequestError(0, "invalid_next_link", endpoint);
      nextUrl = nextLink === undefined ? undefined : this.resolveGraphUrl(nextLink);
      // Collections can exceed the runtime's function-argument limit; never spread a page into push.
      for (const item of page.value) items.push(item);
      onPage?.(items.length);
    }

    return items;
  }

  async getOne<T>(endpoint: string, checkActive?: GraphReadGuard): Promise<T> {
    return this.getJson<T>(this.resolveGraphUrl(endpoint), endpoint, checkActive);
  }

  private async getPage<T>(url: string, checkActive?: GraphReadGuard): Promise<GraphPage<T>> {
    return this.getJson<GraphPage<T>>(url, new URL(this.resolveGraphUrl(url)).pathname, checkActive);
  }

  private async getJson<T>(url: string, endpoint: string, checkActive?: GraphReadGuard): Promise<T> {
    const safeUrl = this.resolveGraphUrl(url);

    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      await checkActive?.();
      const readGuard = new ReadGuardOptions(checkActive);
      let response: Response | undefined;
      try {
        response = await this.sdkClient.api(safeUrl).middlewareOptions([readGuard]).responseType(ResponseType.RAW).get() as Response;
        await readGuard.verify();
        if (response.ok) {
          // Fetch resolves at headers. A connection can still fail or time out
          // while its body is read; keep that work inside the guarded retry.
          const value = await response.json() as T;
          await readGuard.verify();
          return value;
        }
      } catch (error) {
        await releaseResponse(response);
        // The SDK wraps middleware errors. Preserve the caller's original stop reason.
        if (readGuard.interruption) throw readGuard.interruption.reason;
        await checkActive?.();
        if (error instanceof SyntaxError) throw new GraphRequestError(0, "invalid_json", endpoint);
        if (attempt >= this.maxRetries) throw new GraphRequestError(0, "network_error", endpoint);
        await this.waitBeforeRetry(safeUrl, 0, attempt, null, checkActive);
        continue;
      }

      if ([408, 429, 500, 502, 503, 504].includes(response.status) && attempt < this.maxRetries) {
        await releaseResponse(response);
        await this.waitBeforeRetry(safeUrl, response.status, attempt, response.headers, checkActive);
        continue;
      }

      const code = await safeErrorCode(response);
      throw new GraphRequestError(response.status, code, endpoint);
    }

    throw new GraphRequestError(0, "retry_exhausted", endpoint);
  }

  private async waitBeforeRetry(url: string, status: number, attempt: number, headers: Headers | null, checkActive?: GraphReadGuard): Promise<void> {
    const delayMs = Math.min(retryDelay(headers, attempt, this.random), this.maxRetryDelayMs);
    this.onRetry?.({ endpoint: new URL(url).pathname, status, attempt: attempt + 1, delayMs });
    if (!checkActive) { await this.sleep(delayMs); return; }
    await checkActive();
    // A long Retry-After must not prevent cancellation or keep a lost lease alive.
    for (let remaining = delayMs; remaining > 0;) {
      const interval = Math.min(remaining, 1_000);
      await this.sleep(interval);
      await checkActive();
      remaining -= interval;
    }
  }

  private resolveGraphUrl(value: string): string {
    const url = value.startsWith("http") ? new URL(value) : new URL(value.replace(/^\//, ""), GRAPH_ROOT);
    // Stryker disable next-line ConditionalExpression: any non-HTTPS URL also fails the origin check, so the protocol test cannot be the deciding one on its own.
    if (url.protocol !== "https:" || url.origin !== GRAPH_ORIGIN || !url.pathname.startsWith("/v1.0/")) {
      throw new GraphRequestError(0, "invalid_next_link", url.pathname);
    }
    return url.toString();
  }
}

/** Release an abandoned fetch body before backoff or an ownership interruption. */
async function releaseResponse(response: Response | undefined): Promise<void> {
  // A failed/consumed body can reject cancellation; cleanup must not hide the
  // original error or turn an explicit cancellation into another Graph attempt.
  try { await response?.body?.cancel(); } catch { /* Already closed or unavailable. */ }
}

/**
 * The read-only guard the SDK client is built with: every request is forced to GET,
 * carries a freshly resolved bearer token, and refuses caching and redirects.
 * Exported so tests can drive the guard directly — the SDK never issues a write, so
 * the rejection path is otherwise unreachable, and it is the control that keeps a
 * caller (or a future SDK change) from turning a read client into a write client.
 */
export function createReadOnlyMiddleware(options: {
  accessToken: AccessTokenProvider;
  fetchImpl: typeof fetch;
  requestTimeoutMs: number;
}): Middleware {
  return {
    execute: async (context: Context) => {
      const method = context.options?.method ?? "GET";
      if (method !== "GET") throw new GraphRequestError(0, "write_method_rejected", new URL(String(context.request)).pathname);
      const token = typeof options.accessToken === "string" ? options.accessToken : await options.accessToken();
      const readGuard = context.middlewareControl?.getMiddlewareOptions(ReadGuardOptions) as ReadGuardOptions | undefined;
      await readGuard?.verify();
      if (!token.trim()) throw new Error("token_unavailable");
      context.response = await options.fetchImpl(context.request, {
        ...context.options,
        method: "GET",
        headers: { ...context.options?.headers, Accept: "application/json", Authorization: `Bearer ${token}` },
        cache: "no-store",
        redirect: "error",
        signal: AbortSignal.timeout(options.requestTimeoutMs),
      });
    },
  };
}

function retryDelay(headers: Headers | null, attempt: number, random: () => number): number {
  // Stryker disable next-line StringLiteral: any non-numeric placeholder parses to NaN exactly as the empty string does.
  const milliseconds = Number.parseInt(headers?.get("x-ms-retry-after-ms") ?? "", 10);
  if (Number.isFinite(milliseconds) && milliseconds >= 0) return milliseconds;
  // Stryker disable next-line MethodExpression: a blank header parses to NaN with or without the trim, landing on the same exponential fallback.
  const retryAfter = headers?.get("retry-after")?.trim();
  // Stryker disable next-line ConditionalExpression: an absent header parses to NaN inside the block and falls through to the same fallback.
  if (retryAfter) {
    const seconds = Number.parseInt(retryAfter, 10);
    if (Number.isFinite(seconds)) return Math.max(seconds, 1) * 1_000;
    const date = Date.parse(retryAfter);
    if (Number.isFinite(date)) return Math.max(date - Date.now(), 1_000);
  }
  const exponential = Math.min(2 ** attempt * 1_000, 30_000);
  return Math.round(exponential * (0.8 + random() * 0.4));
}

async function safeErrorCode(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as { error?: { code?: unknown } };
    // Stryker disable next-line OptionalChaining: reading through a missing `error` throws into the catch below, which returns the same code.
    return typeof body.error?.code === "string" ? body.error.code : "request_failed";
  } catch {
    return "request_failed";
  }
}
import { Client, ResponseType, type Context, type Middleware } from "@microsoft/microsoft-graph-client";
