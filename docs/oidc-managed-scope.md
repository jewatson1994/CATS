# CATS-managed OIDC scope

CATS can use a validated OIDC claim to establish role eligibility while administrators assign each person's service or group scope in CATS. A matching role alone grants no service access. Each CATS-managed assignment is tied to one role; a stronger role cannot borrow the scope of another role.

In Configuration, choose **CATS-managed** for a claim mapping. In Accounts, select the user, role, service or group, and the CATS-managed assignment source. A group assignment covers that group's services. A service assignment covers only that service, including when a group is also selected. Existing fixed global, group, and service mappings retain their original behavior until explicitly changed.

The Accounts view shows matched claim mappings, assignment sources, whether each assignment is active, and resulting permissions. The application-permission list describes access outside an individual service. User and role administration, audit viewing, template management, service deletion, and validator administration require a global grant. Group configuration authority remains limited to its assigned group. Service-scoped roles cannot administer accounts or other groups.

Leaving both service and group empty for a CATS-managed assignment requires selecting the explicit global confirmation. This grants that role across all services, only while the user remains eligible. An independent local grant remains active independently of OIDC roles; retain a deliberately configured local recovery administrator. Do not use an independent local grant when access should depend on an OIDC role.

## Converting an existing broad mapping

1. Review the existing global or fixed mapping and the users who receive it. Assign each user's intended CATS-managed scope for that role.
2. Edit the mapping to CATS-managed and preview its effect. The preview lists current and proposed service permissions and application permissions for affected users. Users with no assigned scope lose service access.
3. Review the preview, then save. Changing the form or affected access invalidates the preview and requires another review. No access changes occur during preview.
4. Check affected users in Accounts. Existing browser sessions use the updated grants on their next request.

Conversion removes that mapping's old OIDC grants while retaining independently assigned local and CATS-managed grants. A conversion of the same claim and role retains the user's last validated eligibility. Changing the claim or role, or changing fixed scope, requires another validated login before the mapping grants access again. Disabling or deleting a mapping removes its effect immediately. Missing claims at the next validated login remove eligibility but preserve the administrator's stored scope assignments for later reactivation.

Eligibility reflects the last validated sign-in; CATS does not poll the identity provider for role changes. Local assignment and mapping changes affect active sessions immediately. Mapping changes, eligibility synchronization, and grant changes are audited. No new environment variables or Compose settings are required; startup applies the additive database schema changes and existing mappings default to fixed scope.
