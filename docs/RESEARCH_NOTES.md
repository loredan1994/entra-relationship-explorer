# Research notes

The product direction combines three proven patterns:

1. **Microsoft Entra governance:** at-a-glance inventory and actionable status cards.
2. **Security graph exploration:** search, filtering, bounded path views, and an entity inspector.
3. **Evidence-first administration:** every conclusion links back to the underlying directory object and API source.

## Primary references

- [Microsoft: service principals](https://learn.microsoft.com/en-us/entra/architecture/service-accounts-principal)
- [Microsoft: identity governance dashboard](https://learn.microsoft.com/en-us/entra/id-governance/governance-dashboard)
- [Microsoft: security operations for applications](https://learn.microsoft.com/en-us/entra/architecture/security-operations-applications)
- [Microsoft: list applications](https://learn.microsoft.com/en-us/graph/api/application-list?view=graph-rest-1.0)
- [Microsoft: list service principals](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list?view=graph-rest-1.0)
- [Microsoft: incoming app-role assignments](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list-approleassignedto?view=graph-rest-1.0)
- [Microsoft: outgoing app-role assignments](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list-approleassignments?view=graph-rest-1.0)
- [Microsoft: delegated grants](https://learn.microsoft.com/en-us/graph/api/oauth2permissiongrant-list?view=graph-rest-1.0)
- [Microsoft: sign-ins](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0)
- [BloodHound graph search](https://bloodhound.specterops.io/analyze-data/explore/search)
- [BloodHound attack-path findings](https://bloodhound.specterops.io/analyze-data/findings/attack-paths)

Microsoft Graph permission requirements change over time. Recheck the current documentation before any tenant connection or administrator-consent request.

