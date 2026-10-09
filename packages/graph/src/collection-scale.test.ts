import { describe, expect, it, vi } from "vitest";
import { ReadOnlyGraphClient } from "./client";
import { scanTenant } from "./scanner";
import { jsonResponse, SCANNED_AT, TENANT } from "./test-support";

// Above V8's function-argument ceiling, but well below the documented endpoint cap.
const LARGE_COLLECTION_SIZE = 150_000;
const PAGE_SIZE = 1_000;

describe("large Graph collections", () => {
  it.each(["/users", "/groups/large-group/members"])("retains every paginated record from %s without an argument-stack overflow", async (collectionPath) => {
    let collectionPages = 0;
    const fetchImpl = vi.fn<typeof fetch>(async (input) => {
      const url = new URL(String(input));
      if (url.pathname === `/v1.0${collectionPath}`) {
        const offset = Number(url.searchParams.get("$skiptoken") ?? 0);
        const value = Array.from({ length: PAGE_SIZE }, (_, index) => ({
          id: `person-${offset + index}`, displayName: `Person ${offset + index}`, userType: "Member",
        }));
        const nextOffset = offset + PAGE_SIZE;
        collectionPages++;
        return jsonResponse({
          value,
          ...(nextOffset < LARGE_COLLECTION_SIZE ? { "@odata.nextLink": `https://graph.microsoft.com/v1.0${collectionPath}?$skiptoken=${nextOffset}` } : {}),
        });
      }
      return jsonResponse({ value: collectionPath.includes("/members") && url.pathname === "/v1.0/groups"
        ? [{ id: "large-group", displayName: "Large group", securityEnabled: true }]
        : [] });
    });

    const scan = await scanTenant(new ReadOnlyGraphClient("synthetic-token", { fetchImpl }), TENANT, {
      now: () => new Date(SCANNED_AT), concurrency: 1,
    });
    const records = collectionPath === "/users" ? scan.users! : scan.groupMemberships!;

    expect(records).toHaveLength(LARGE_COLLECTION_SIZE);
    expect(records.every(({ record }, index) => record.id === `person-${index}`)).toBe(true);
    expect(records.every(({ endpoint }) => endpoint.startsWith(`${collectionPath}?$select=`))).toBe(true);
    expect(collectionPages).toBe(LARGE_COLLECTION_SIZE / PAGE_SIZE);
    expect(scan.errors).toEqual([]);
    expect(scan.completedStages).toContain("directoryAudits");
    if (collectionPath !== "/users") expect(scan.groupMemberships!.every(({ groupId }) => groupId === "large-group")).toBe(true);
    for (const [, init] of fetchImpl.mock.calls) expect(init?.method).toBe("GET");
  });

  it("accepts a large single page exactly at the configured item cap", async () => {
    const progress = vi.fn();
    const fetchImpl = vi.fn<typeof fetch>(async () => jsonResponse({
      value: Array.from({ length: LARGE_COLLECTION_SIZE }, (_, id) => ({ id })),
    }));
    const records = await new ReadOnlyGraphClient("synthetic-token", {
      fetchImpl, maxItems: LARGE_COLLECTION_SIZE,
    }).getAll<{ id: number }>("/users", progress);

    expect(records).toHaveLength(LARGE_COLLECTION_SIZE);
    expect(records.every(({ id }, index) => id === index)).toBe(true);
    expect(progress).toHaveBeenCalledExactlyOnceWith(LARGE_COLLECTION_SIZE);
  });

  it("reports an item-limit error for an oversized page before appending it or reporting progress", async () => {
    const progress = vi.fn();
    const fetchImpl = vi.fn<typeof fetch>(async () => jsonResponse({
      value: Array.from({ length: LARGE_COLLECTION_SIZE + 1 }, (_, id) => ({ id })),
      "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?$skiptoken=unused",
    }));
    const client = new ReadOnlyGraphClient("synthetic-token", { fetchImpl, maxItems: LARGE_COLLECTION_SIZE });

    await expect(client.getAll("/users", progress)).rejects.toMatchObject({
      name: "GraphRequestError", code: "item_limit", endpoint: "/users",
    });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(progress).not.toHaveBeenCalled();
  });
});
