# Synthetic rule laboratory

The laboratory runs the reviewed, compiled rules against `clean-project-v1`, a synthetic fixture shipped in the domain package. It never connects to Microsoft Graph. Imported files contain declarative expectations and relationship exclusions; tenant snapshots, arbitrary metadata and executable rules are rejected.

In **Investigations → Rule laboratory**, load a positive or negative case, edit the synthetic JSON and select **Replay synthetic case**. The browser shows expected versus actual finding counts, pass/fail status and supporting relationship IDs/endpoints. Editing clears the previous result so an old pass cannot describe a changed case. Replay makes no network write and never uses the connected tenant snapshot.

From the repository root:

```sh
pnpm rule:lab scaffold /tmp/owner-control.json
pnpm rule:lab replay /tmp/owner-control.json
```

Scaffolding refuses to overwrite an existing file. Relative paths resolve from the repository root. Replay prints a JSON result with actual counts and supporting edge IDs/endpoints. A failed expectation exits with status 1. Invalid schema, IDs or rule versions also fail the command. Files are limited to 100 KB.

The scaffold is a negative control: removing ownership and federation relationships must eliminate `ERE-IAM-001` findings, while unrelated direct access can remain. A positive case is:

```json
{
  "schemaVersion": 1,
  "name": "Configured privileged control remains detectable",
  "fixture": "clean-project-v1",
  "removeEdgeIds": [],
  "expectations": [
    { "ruleId": "ERE-IAM-001", "version": 1, "minimum": 1, "maximum": 100 }
  ]
}
```

For a new compiled rule, add its reference, prerequisites, evidence classification and required coverage in `packages/domain/src/rules.ts`. Add a focused synthetic graph in a domain test. Include a positive case, a nearby negative case, partial-coverage behavior and a deterministic finding identity. History rules also need a before/after pair and an unchanged pair. Change the rule version when its meaning changes; replay refuses an expectation for an old version instead of silently accepting a different rule.

The import surface intentionally supports one reviewed fixture and bounded exclusions. Richer graphs and history transitions are authored as TypeScript tests in the repository, subject to code review. The existing rule contracts cover amplification and federation-change history. The lab is a contributor workflow, not a remote rule marketplace.

Run `pnpm test` for the positive, negative, rejected-code and version-mismatch contracts, then `pnpm verify` for the complete product check.
