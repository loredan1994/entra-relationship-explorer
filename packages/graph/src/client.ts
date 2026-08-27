const GRAPH_ORIGIN = "https://graph.microsoft.com";
const GRAPH_ROOT = `${GRAPH_ORIGIN}/v1.0/`;

interface GraphPage<T> {
  value: T[];
  "@odata.nextLink"?: string;
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

  async getAll<T>(endpoint: string, onPage?: (totalItems: number) => void): Promise<T[]> {
    let nextUrl: string | undefined = this.resolveGraphUrl(endpoint);
    const items: T[] = [];
    let pages = 0;

    while (nextUrl) {
      if (++pages > this.maxPages) throw new GraphRequestError(0, "page_limit", endpoint);
      const page: GraphPage<T> = await this.getPage<T>(nextUrl);
      if (!Array.isArray(page.value)) throw new GraphRequestError(0, "invalid_collection", endpoint);
      items.push(...page.value);
      if (items.length > this.maxItems) throw new GraphRequestError(0, "item_limit", endpoint);
      onPage?.(items.length);
      nextUrl = page["@odata.nextLink"] ? this.resolveGraphUrl(page["@odata.nextLink"]) : undefined;
    }

    return items;
  }

  async getOne<T>(endpoint: string): Promise<T> {
    return this.getJson<T>(this.resolveGraphUrl(endpoint), endpoint);
  }

  private async getPage<T>(url: string): Promise<GraphPage<T>> {
    return this.getJson<GraphPage<T>>(url, new URL(this.resolveGraphUrl(url)).pathname);
  }

  private async getJson<T>(url: string, endpoint: string): Promise<T> {
    const safeUrl = this.resolveGraphUrl(url);

    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      let response: Response;
      try {
        response = await this.sdkClient.api(safeUrl).responseType(ResponseType.RAW).get() as Response;
      } catch {
        if (attempt >= this.maxRetries) throw new GraphRequestError(0, "network_error", endpoint);
        await this.waitBeforeRetry(safeUrl, 0, attempt, null);
        continue;
      }

      if (response.ok) return response.json() as Promise<T>;

      if ([408, 429, 500, 502, 503, 504].includes(response.status) && attempt < this.maxRetries) {
        await this.waitBeforeRetry(safeUrl, response.status, attempt, response.headers);
        continue;
      }

      const code = await safeErrorCode(response);
      throw new GraphRequestError(response.status, code, endpoint);
    }

    throw new GraphRequestError(0, "retry_exhausted", endpoint);
  }

  private async waitBeforeRetry(url: string, status: number, attempt: number, headers: Headers | null): Promise<void> {
    const delayMs = Math.min(retryDelay(headers, attempt, this.random), this.maxRetryDelayMs);
    this.onRetry?.({ endpoint: new URL(url).pathname, status, attempt: attempt + 1, delayMs });
    await this.sleep(delayMs);
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
