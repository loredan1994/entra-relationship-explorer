# Entra control-path rule catalog

The rule catalog is trusted, versioned product logic in `packages/domain/src/rules.ts`. Rules operate only on normalized, tenant-scoped snapshot evidence. They do not load executable third-party plugins and they do not change Microsoft Entra.

Every rule declares a stable ID, version, title, required evidence coverage, and public references. Every emitted finding preserves the evidence class, prerequisites, exact source endpoints, object and relationship IDs, uncertainty, and snapshot identity used by the review and export surfaces.

| Rule | Detects | Evidence meaning |
|---|---|---|
| `ERE-IAM-001` | A principal or federated trust controls an application identity whose configured path reaches high-impact application access or an Entra role. | Inferred possibility. The starting principal must first be controlled; federation also requires a token matching the configured issuer, subject, and audience. |
| `ERE-IAM-002` | An existing privilege path becomes more severe, gains terminal permissions, or expands from a scoped administrative-unit assignment to tenant-wide scope between consecutive retained snapshots. | Configured change interpreted as an inferred increase in reach. It does not prove use of the added privilege. |
| `ERE-IAM-003` | Issuer, subject, audience, or parent identity changes for a federated credential whose current path reaches powerful access. | Configured trust change. It does not prove that a matching token was issued or used. |
| `ERE-IAM-004` | A tenant-owned application or managed identity has powerful configured access but no collected accountable owner. | Inferred governance exposure. Missing ownership is not proof that the workload is abandoned or compromised. |

## Contributor contract

Add intelligence through the small `EntraRule` interface. A proposed rule must:

1. Have a repository-reviewed `ERE-IAM-###` identifier and an integer version. Increment the version when detection or interpretation changes materially.
2. Declare the exact evidence coverage it needs and remain conservative when a snapshot is partial.
3. Use normalized evidence only, remain deterministic, and reject cross-tenant or incorrectly ordered history before evaluation.
4. Describe prerequisites and uncertainty in plain English. Never turn configured access into a claim of observed use.
5. Produce stable finding IDs from durable object, relationship, and change identities—not display names.
6. Include public primary references and exact Graph source endpoints already preserved by the evidence graph.
7. Add fixture-based contract tests for the positive case, adjacent non-finding cases, deterministic output, partial evidence, and tenant isolation.

Runtime rule plugins remain intentionally out of scope. Executable rules are trusted code and receive the same review, coverage, mutation, and GET-only verification as the rest of the product.
