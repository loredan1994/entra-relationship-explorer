## What this changes

<!-- The problem being solved, not a restatement of the diff. Link the issue if one exists. -->

Closes #

## How it was verified

<!-- The command you ran, the test you added, the screenshot for a visual change. -->

- [ ] `pnpm run verify` passes locally

## The non-negotiables

These are the rules from [CONTRIBUTING.md](../blob/main/CONTRIBUTING.md). Confirm
each one, or explain in the section below why it does not apply.

- [ ] No code path writes to Microsoft Entra; Graph transport remains GET-only.
- [ ] No new Microsoft Graph scope. *(If there is one, justify it below.)*
- [ ] Configured access, observed activity, inferred possibility, and missing
      evidence remain distinct, and nothing implies a permission is used merely
      because it is configured.
- [ ] Every new relationship is explainable with object IDs, relationship type,
      and source Graph endpoint.
- [ ] No secret, token, certificate, tenant export, or real tenant/client GUID
      is added to the repository.
- [ ] Tenant scoping is preserved; every new database read is tenant-keyed.
- [ ] Visual changes follow [DESIGN.md](../blob/main/DESIGN.md).

## Security and privacy impact

<!-- Say "none" if that is true. Otherwise: what data does this touch, where does it
     go, and who can reach it? Flag anything affecting auth, encryption, sessions,
     scopes, or exports. -->

## Notes for the reviewer

<!-- Trade-offs, things you were unsure about, follow-up work you deliberately left out. -->

---

- [ ] My commits are signed off (`git commit -s`) per the
      [DCO](https://developercertificate.org/).
