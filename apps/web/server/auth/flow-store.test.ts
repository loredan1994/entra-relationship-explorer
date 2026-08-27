import { beforeEach, describe, expect, it, vi } from "vitest";
import type { LiveEntraConfig } from "../config-core";

const TENANT = "11111111-1111-4111-8111-111111111111";

const createAuthFlowRow = vi.fn();
const consumeAuthFlowRow = vi.fn();

vi.mock("../backend", () => ({
  getBackend: async () => ({ createAuthFlow: createAuthFlowRow, consumeAuthFlow: consumeAuthFlowRow }),
}));

const { consumeAuthFlow, createAuthFlow } = await import("./flow-store");

const config = { tenantId: TENANT } as unknown as LiveEntraConfig;

beforeEach(() => {
  vi.clearAllMocks();
  vi.useRealTimers();
});

describe("starting a sign-in", () => {
  it("mints an unguessable state and a fresh flow identifier", async () => {
    const { flowId, state } = await createAuthFlow(config, "code-verifier");
    expect(flowId).toMatch(/^[0-9a-f-]{36}$/);
    // 32 random bytes, base64url encoded, carries no padding.
    expect(state).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(state).not.toContain("=");
  });

  it("does not repeat a state or a flow id across sign-ins", async () => {
    const first = await createAuthFlow(config, "verifier");
    const second = await createAuthFlow(config, "verifier");
    expect(first.state).not.toBe(second.state);
    expect(first.flowId).not.toBe(second.flowId);
  });

  it("stores the flow against the configured tenant with the PKCE verifier", async () => {
    const { flowId, state } = await createAuthFlow(config, "code-verifier");
    expect(createAuthFlowRow).toHaveBeenCalledWith(expect.objectContaining({
      id: flowId, tenantId: TENANT, state, verifier: "code-verifier",
    }));
  });

  it("expires an unfinished sign-in after ten minutes", async () => {
    vi.useFakeTimers().setSystemTime(new Date("2026-08-26T10:00:00.000Z"));
    await createAuthFlow(config, "verifier");
    expect(createAuthFlowRow.mock.calls[0]![0]).toMatchObject({
      expiresAt: Date.parse("2026-08-26T10:10:00.000Z"),
    });
  });
});

describe("completing a sign-in", () => {
  it("refuses a callback with no flow cookie or no returned state", async () => {
    expect(await consumeAuthFlow(config, undefined, "state")).toBeNull();
    expect(await consumeAuthFlow(config, "flow-1", null)).toBeNull();
    expect(await consumeAuthFlow(config, undefined, null)).toBeNull();
    expect(consumeAuthFlowRow).not.toHaveBeenCalled();
  });

  it("refuses a callback whose returned state is an empty string", async () => {
    expect(await consumeAuthFlow(config, "flow-1", "")).toBeNull();
    expect(consumeAuthFlowRow).not.toHaveBeenCalled();
  });

  it("consumes the flow scoped to the configured tenant", async () => {
    consumeAuthFlowRow.mockResolvedValue({ id: "flow-1", tenantId: TENANT, state: "s", verifier: "v", expiresAt: Date.now() });
    const flow = await consumeAuthFlow(config, "flow-1", "returned-state");
    expect(consumeAuthFlowRow).toHaveBeenCalledWith("flow-1", TENANT, "returned-state");
    expect(flow).toMatchObject({ verifier: "v" });
  });

  it("passes through a rejected or already-used flow", async () => {
    consumeAuthFlowRow.mockResolvedValue(null);
    expect(await consumeAuthFlow(config, "flow-1", "returned-state")).toBeNull();
  });
});
