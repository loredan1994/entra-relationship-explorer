import { describe, expect, it, vi } from "vitest";
import { ReadOnlyGraphClient } from "./client";
import { scanTenant } from "./scanner";

describe("scanTenant", () => {
  it("keeps credential metadata but drops secret-like response fields", async () => {
    const responses = [
      { value: [{ id: "app-object", appId: "app-id", displayName: "App", publisherDomain: null, appRoles: [], passwordCredentials: [{ keyId: "key-1", displayName: "Credential", startDateTime: "2026-01-01T00:00:00Z", endDateTime: "2027-01-01T00:00:00Z", secretText: "must-not-survive", customKeyIdentifier: "private-material" }], keyCredentials: [] }] },
      { value: [{ id: "sp-object", appId: "app-id", displayName: "App", publisherName: null, servicePrincipalType: "Application", appRoles: [], passwordCredentials: [], keyCredentials: [] }] },
      { value: [] },
      { value: [] },
      { value: [] },
      { value: [] },
    ];
    const fetchImpl = vi.fn<typeof fetch>();
    for (const response of responses) fetchImpl.mockResolvedValueOnce(new Response(JSON.stringify(response), { status: 200, headers: { "content-type": "application/json" } }));
    const scan = await scanTenant(new ReadOnlyGraphClient("sensitive-token", { fetchImpl }), "11111111-1111-4111-8111-111111111111", { concurrency: 1 });
    const serialized = JSON.stringify(scan);
    expect(serialized).toContain("key-1");
    expect(serialized).not.toContain("must-not-survive");
    expect(serialized).not.toContain("private-material");
    expect(serialized).not.toContain("sensitive-token");
    expect(fetchImpl).toHaveBeenCalledTimes(6);
  });
});
