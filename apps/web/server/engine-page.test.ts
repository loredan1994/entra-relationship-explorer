import { expect, it, vi } from "vitest";
import { cleanProjectFixture } from "@entra-explorer/domain";
import { loadSnapshotContext } from "./current-snapshot";
import EnginePage from "../app/engine/page";

vi.mock("./current-snapshot", () => ({ loadSnapshotContext: vi.fn() }));

it.each<[string | undefined, number]>([[undefined, 1], ["proof", 1], ["authorization", 1], ["plans", 1], ["policy", 1], ["federation", 1], ["rotation", 1], ["gaps", 1], ["verify", 1], ["unknown", 1], ["time", 10], ["contracts", 2]])("only requests the snapshot history needed for the %s workflow", async (view, count) => {
  vi.mocked(loadSnapshotContext).mockResolvedValue({ snapshot: cleanProjectFixture, history: [cleanProjectFixture], state: "demo", liveEnabled: false });
  await EnginePage({ searchParams: Promise.resolve({ view }) });
  expect(loadSnapshotContext).toHaveBeenLastCalledWith(count);
});
