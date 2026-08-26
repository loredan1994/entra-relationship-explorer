# Project instructions

Read `README.md`, `DESIGN.md`, and `docs/SECURITY_PRIVACY.md` before changing the product.

## Non-negotiable rules

1. Keep the product read-only until the owner explicitly approves a separate write-capable phase.
2. Never request more Microsoft Graph permission than a feature requires.
3. Visually and technically distinguish configured access from observed activity.
4. Every graph connection must be explainable with object IDs, relationship type, and source endpoint.
5. Never store client secrets, access tokens, certificates, or exported tenant data in Git.
6. Preserve tenant boundaries. A scan result belongs to exactly one tenant.
7. Follow the design tokens and component rules in `DESIGN.md`.

## Product language

Use plain English first and the Microsoft term second, for example: “Enterprise application (service principal).” Never imply that an API permission is being used merely because it is configured.

