import Link from "next/link";
import { AppShell } from "@/components/app-shell";
import { PageHeading } from "@/components/page-heading";
import { workspaceTools } from "@/components/workspace-tools";

export const dynamic = "force-dynamic";

export default function GuidePage() {
  return <AppShell><div className="page-container workspace-guide">
    <PageHeading eyebrow="Workspace guide" title="Understand access. Follow the evidence."
      description="Entra Relationship Explorer helps administrators and reviewers investigate one Microsoft Entra tenant from a read-only snapshot. Start with a question, inspect the recorded facts, and keep your review beside the evidence."
      actions={<Link className="button button-primary" href="/map">Open relationship map</Link>} />
    <section className="guide-boundary" aria-labelledby="boundary-title">
      <div><p className="eyebrow">The product boundary</p><h2 id="boundary-title">Reads Entra. Keeps your review local.</h2></div>
      <p>The collector never grants permissions, removes assignments, rotates credentials or applies remediation. Review decisions are saved in your own workspace; what-if plans only model a copy of the displayed snapshot.</p>
    </section>
    <section aria-labelledby="workflow-title">
      <div className="section-heading"><div><p className="eyebrow">Choose your next step</p><h2 id="workflow-title">Start with a question</h2></div></div>
      <div className="workflow-list">{workspaceTools.map(tool => <Link className="workflow-link" href={tool.href} key={tool.id}><span><strong>{tool.question}</strong><small>{tool.description}</small></span><span className="workflow-destination">{tool.title} <span aria-hidden="true">→</span></span></Link>)}</div>
    </section>
    <div className="guide-columns">
      <section className="panel guide-panel" aria-labelledby="evidence-title"><p className="eyebrow">Read claims correctly</p><h2 id="evidence-title">Four kinds of evidence</h2>
        <dl className="evidence-dictionary">
          <div><dt>Configured</dt><dd>A recorded setting, grant or relationship. It does not prove access was used or is effective in every context.</dd></div>
          <div><dt>Observed</dt><dd>A recorded event within a collection window. A successful sign-in does not prove a particular permission was exercised.</dd></div>
          <div><dt>Inferred</dt><dd>A possible path derived from recorded relationships and rule assumptions. It is not evidence of exploitation.</dd></div>
          <div><dt>Missing</dt><dd>Evidence was not collected, was unavailable or hit a limit. Unknown is not the same as absent, safe or disabled.</dd></div>
        </dl>
        <Link className="text-link" href="/investigations?view=coverage">Inspect this snapshot’s coverage →</Link>
      </section>
      <section className="panel guide-panel" aria-labelledby="start-title"><p className="eyebrow">From sample to your tenant</p><h2 id="start-title">A short first investigation</h2>
        <ol className="guide-steps">
          <li><strong>Explore the sample.</strong> The demo uses synthetic people and applications. No Microsoft account is needed.</li>
          <li><strong>Connect deliberately.</strong> Configure one tenant you administer, review the two core read permissions in Settings, sign in and start a scan.</li>
          <li><strong>Check coverage first.</strong> Optional evidence needs explicit configuration and access. A completed scan can still have partial or unavailable datasets.</li>
          <li><strong>Inspect, compare, decide.</strong> Open source evidence, compare retained scans and record your reasoning. Handle any actual tenant change outside this tool.</li>
        </ol>
        <Link className="text-link" href="/settings">Connection and data settings →</Link>
      </section>
    </div>
    <section className="panel guide-panel" aria-labelledby="navigation-title"><h2 id="navigation-title">Keep your investigation in view</h2><p>Inspect reveals the selected evidence and moves keyboard focus to it. Map shows up to 15 objects and 50 connections after filtering; its scope message explains omitted relationships. Table preserves the complete filtered inventory.</p><p>Failed review reads and browser saves offer a retry without discarding the current draft. An export starts only when you choose it and uses the displayed snapshot. If your session expires or a newer scan arrives, the download explains what to do and keeps your edits in place. Copy unsaved drafts before deliberately reloading or leaving the page.</p></section>
    <section className="panel guide-panel" aria-labelledby="data-title"><h2 id="data-title">Where your data goes</h2><p>Live snapshots, sessions and review decisions are encrypted in your own PostgreSQL database. Evidence retention is 30 days. Demo decisions use this browser’s local storage; what-if calculations stay in memory. Exports are created only when requested and can contain sensitive tenant identifiers. Sanitized does not mean anonymous.</p><p>This is a local, single-tenant workspace. It does not provide hosted multi-tenancy, unattended scan schedules or notifications. Sign-in evidence is optional and incomplete for workload activity; group membership and path traversal also have documented limits.</p></section>
    <section className="guide-footer" aria-labelledby="contribute-title"><div><h2 id="contribute-title">Understand a rule or contribute one</h2><p>The synthetic rule laboratory replays declarative cases against the bundled sample. It cannot execute imported code or connect to your tenant.</p></div><div className="guide-links"><Link className="text-link" href="/investigations?view=rules">Open rule laboratory →</Link><a className="text-link" href="https://github.com/loredan1994/entra-relationship-explorer#readme">Read the setup and contributor docs ↗</a></div></section>
  </div></AppShell>;
}
