import { describe, expect, it, vi } from "vitest";
import { ReadOnlyGraphClient } from "./client";
import { scanTenant } from "./scanner";
import { TENANT, clientFor, routedFetch } from "./test-support";

describe("collection continuation integrity", () => {
  it.each([null, false, 0, "", "   ", [], {}].map(nextLink => ({ nextLink })))("rejects a present malformed next link: $nextLink", async ({ nextLink }) => {
    const fetchImpl = vi.fn<typeof fetch>(async () => Response.json({ value: [{ id: "first-page" }], "@odata.nextLink": nextLink }));
    const onPage = vi.fn();
    await expect(new ReadOnlyGraphClient("synthetic-token", { fetchImpl }).getAll("/applications", onPage))
      .rejects.toMatchObject({ code: "invalid_next_link" });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(onPage).not.toHaveBeenCalled();
  });

  it.each([null, true, 7, "response", []].map(body => ({ body })))("rejects an invalid collection envelope: $body", async ({ body }) => {
    const fetchImpl = vi.fn<typeof fetch>(async () => Response.json(body));
    await expect(new ReadOnlyGraphClient("synthetic-token", { fetchImpl }).getAll("/applications"))
      .rejects.toMatchObject({ code: "invalid_collection" });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("does not certify a parent or dependent collector complete after a malformed continuation", async () => {
    const recorder = routedFetch({
      "/applications?": { value: [{ id: "app-1", appId: "client-1", displayName: "Partial application" }], "@odata.nextLink": false },
    });
    const scan = await scanTenant(clientFor(recorder), TENANT);
    expect(scan.applications).toEqual([]);
    expect(scan.coverage?.find(item => item.id === "applications")).toMatchObject({ state: "unavailable", itemCount: 0, endpoints: [] });
    expect(scan.coverage?.find(item => item.id === "owners")?.state).toBe("partial");
    expect(scan.coverage?.find(item => item.id === "federatedIdentityCredentials")?.state).toBe("partial");
    expect(scan.errors).toContainEqual(expect.objectContaining({ code: "invalid_next_link" }));
    expect(recorder.requestedPath("/applications/app-1/")).toBe(false);
  });

  it("follows an empty intermediate page and stops only when the next link is absent", async () => {
    const nextLink = "https://graph.microsoft.com/v1.0/applications?$skiptoken=synthetic%2Bnext%3D&$select=id";
    const fetchImpl = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(Response.json({ value: [], "@odata.nextLink": nextLink }))
      .mockResolvedValueOnce(Response.json({ value: [{ id: "last-page" }] }));
    const onPage = vi.fn();
    await expect(new ReadOnlyGraphClient("synthetic-token", { fetchImpl }).getAll("/applications", onPage)).resolves.toEqual([{ id: "last-page" }]);
    const requested = new URL(String(fetchImpl.mock.calls[1]?.[0]));
    expect(requested.origin + requested.pathname).toBe("https://graph.microsoft.com/v1.0/applications");
    expect([...requested.searchParams].sort()).toEqual([...new URL(nextLink).searchParams].sort());
    expect(onPage.mock.calls).toEqual([[0], [1]]);
  });
});

function openBody(status: number, cancel: () => void | Promise<void>): Response {
  // A stalled response models a server that returned headers but has not finished its body.
  return new Response(new ReadableStream({ cancel }, { highWaterMark: 0 }), { status, headers: { "retry-after": "2" } });
}

describe("abandoned Graph response resources", () => {
  it.each([408, 429, 500, 502, 503, 504])("releases a %s response before retry backoff and the next GET", async status => {
    const events: string[] = [];
    const cancel = vi.fn(() => { events.push("cancel"); });
    const sleep = vi.fn(async () => { events.push("wait"); });
    const fetchImpl = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(openBody(status, cancel))
      .mockImplementationOnce(async () => { events.push("fetch"); return Response.json({ value: [{ id: "recovered" }] }); });
    await expect(new ReadOnlyGraphClient("synthetic-token", { fetchImpl, sleep }).getAll("/applications")).resolves.toEqual([{ id: "recovered" }]);
    expect(events).toEqual(["cancel", "wait", "fetch"]);
    expect(cancel).toHaveBeenCalledTimes(1);
    expect(sleep).toHaveBeenCalledWith(2_000);
    expect(fetchImpl.mock.calls.every(([, options]) => options?.method === "GET")).toBe(true);
  });

  it("does not let cancellation failure replace the bounded retry result", async () => {
    const cancel = vi.fn(async () => { throw new Error("synthetic stream already errored"); });
    const fetchImpl = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(openBody(503, cancel))
      .mockResolvedValueOnce(Response.json({ value: [] }));
    await expect(new ReadOnlyGraphClient("synthetic-token", { fetchImpl, sleep: async () => {} }).getAll("/applications")).resolves.toEqual([]);
    expect(cancel).toHaveBeenCalledTimes(1);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it.each([200, 403, 429])("releases a %s body when scan ownership is lost after headers without retrying", async status => {
    const cancel = vi.fn();
    let interrupted = false;
    const reason = new Error("synthetic lease was lost");
    const checkActive = async () => { if (interrupted) throw reason; };
    const fetchImpl = vi.fn<typeof fetch>(async () => { interrupted = true; return openBody(status, cancel); });
    const sleep = vi.fn(async () => {});
    await expect(new ReadOnlyGraphClient("synthetic-token", { fetchImpl, sleep }).getAll("/applications", undefined, checkActive)).rejects.toBe(reason);
    expect(cancel).toHaveBeenCalledTimes(1);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(sleep).not.toHaveBeenCalled();
  });

  it("keeps a final Graph error body available for its sanitized error code", async () => {
    const response = Response.json({ error: { code: "Authorization_RequestDenied", message: "synthetic-private-body" } }, { status: 403 });
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(response);
    const reason = await new ReadOnlyGraphClient("synthetic-token", { fetchImpl }).getAll("/applications").catch((error: unknown) => error);
    expect(reason).toMatchObject({ status: 403, code: "Authorization_RequestDenied" });
    expect(String(reason)).not.toContain("synthetic-private-body");
    expect(response.bodyUsed).toBe(true);
  });
});
