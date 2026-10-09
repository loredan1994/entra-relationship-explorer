import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { analyzeFindingLifecycle, analyzeTenantIntelligenceHistory, cleanProjectFixture, coverageMatrix } from "@entra-explorer/domain";
import type { ThreatReview } from "@entra-explorer/backend";
import { expect, it } from "vitest";
import { ThreatWorkspace } from "../components/threat-workspace";

it("renders every saved queue status and due acceptance before selected review details are loaded", () => {
  const history = [cleanProjectFixture];
  const intelligence = analyzeTenantIntelligenceHistory(history);
  const accepted = intelligence.findings[1]!, mitigating = intelligence.findings[2]!;
  const prior: ThreatReview = { findingId: mitigating.id, snapshotId: "previous-scan", tenantId: cleanProjectFixture.tenant.tenantId, disposition: "accepted", expiresAt: "2026-09-01", owner: "Prior owner", assumption: "Prior rationale", updatedAt: "2026-09-01T10:00:00Z" };
  const html = renderToStaticMarkup(createElement(ThreatWorkspace, {
    coverage: coverageMatrix(cleanProjectFixture), intelligence, lifecycle: analyzeFindingLifecycle(history),
    currentReviews: [{ findingId: accepted.id, disposition: "accepted", expiresAt: "2026-10-14" }, { findingId: mitigating.id, disposition: "mitigating", expiresAt: null }],
    priorReviews: [prior], today: "2026-10-09", tenantLabel: "Synthetic test", snapshotId: cleanProjectFixture.id,
    completion: "complete", persistence: "server",
  }));
  const queue = html.slice(html.indexOf('aria-label="Prioritized findings"'), html.indexOf('<section class="finding-detail"'));
  expect(queue).toContain("<em>accepted</em>");
  expect(queue).toContain("<em>mitigating</em>");
  expect(html).toContain("<span>1</span>acceptance due");
  expect(html).toContain('<fieldset disabled="">');
  expect(html).toContain('disabled="">Save decision</button>');
});
