# Third-party notices

Entra Relationship Explorer is original application code. The following projects are directly incorporated in the current build or runtime. No project listed here sponsors or endorses this product.

| Component | Version | License | Use / modifications |
|---|---:|---|---|
| Microsoft Graph JavaScript Client Library | 3.0.7 | MIT | Installed for the collector integration boundary; no upstream source modifications. The hardened product transport still constrains every request to HTTPS GET and validates continuation links. |
| Cytoscape.js | 3.34.1 | MIT | Headless relationship layout feeding the product's accessible HTML graph and table; no upstream source modifications. |
| Next.js | 16.3.3 | MIT | Web application framework; no upstream source modifications. |
| React / React DOM | 19.2.7 | MIT | User interface runtime; no upstream source modifications. |
| MSAL Node | 5.4.3 | MIT | Microsoft identity authorization-code and token-cache integration; no upstream source modifications. |
| node-postgres (`pg`) | 8.23.0 | MIT | Parameterized PostgreSQL access; no upstream source modifications. |
| server-only | 0.0.1 | MIT | React server-boundary marker; no upstream source modifications. |
| tsx | 4.23.12 | MIT | Migration and worker TypeScript runtime; no upstream source modifications. |
| PostgreSQL container | 17 Alpine (digest pinned in `compose.yaml`) | PostgreSQL License | Local tenant-isolated persistence; no upstream source modifications. |
| TypeScript | 5.9.2 | Apache-2.0 | Build tooling only. |
| Playwright | 1.62.1 | Apache-2.0 | Test tooling only. |
| Vitest | 3.2.6 | MIT | Test tooling only. |
| axe-core Playwright | 4.13.0 | MPL-2.0 | Accessibility test tooling only. |
| ESLint / @eslint/js | 10.9.1 / 10.0.1 | MIT | Static-analysis tooling only. |
| typescript-eslint | 8.68.0 | MIT | TypeScript lint integration only. |
| MITRE Attack Flow specification | 2.0.0 | Apache-2.0 | Standards format used by an original STIX 2.1 serializer; no upstream application code or assets are embedded. |

The complete resolved transitive dependency set is pinned in `pnpm-lock.yaml`. The machine-readable direct inventory is `oss-inventory.json`.

## MITRE ATT&CK® attribution

The product references MITRE ATT&CK technique identifiers and names for threat classification.

© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.

MITRE ATT&CK® is a registered trademark of The MITRE Corporation. Its inclusion does not imply affiliation, sponsorship, certification, or endorsement. ATT&CK information is provided “as is” under MITRE's terms of use: <https://attack.mitre.org/resources/terms-of-use/>.

## Excluded components

No BloodHound, AzureHound, Maester test pack, Threat Dragon, Threagile, ZAP, Trivy, Gitleaks, Security Copilot, Sentinel, or IriusRisk code is embedded or redistributed in the application. AWS Threat Composer was evaluated as a conceptual reference only. MITRE Attack Flow is used solely as an Apache-2.0 interoperability specification through original serializer code.
