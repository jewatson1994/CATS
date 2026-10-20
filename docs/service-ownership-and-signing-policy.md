# Service ownership and signing validity

Each service has one owning group. CATS signing keys remain centrally managed in Configuration; the owning group controls approval validity under General Policy > Signing validity. The approving person's other group memberships do not select the service policy.

## Ownership

- Edit service uses a required single Owning group selector.
- New pipeline services must supply one group. Existing services can omit it to retain their owner; a different group is rejected. Transfer ownership through Edit service instead.
- Creating a service from a bundle requires selecting one existing local owning group. Imported group assignments do not determine local ownership.
- Ownership transfers require administration of both source and destination groups. Unassigned legacy services require a global administrator.
- Database constraints prevent adding a second owner. Existing ambiguous assignments are preserved for explicit administrator reconciliation, rather than silently choosing a group. Startup logs identify affected service IDs. Such services remain readable using global policy defaults, but new approvals and ingestion are blocked until ownership is corrected. A unique index is installed once conflicts have been resolved and the application restarts.

## Validity

An authorized group administrator sets a validity period of 1 to 3650 days. A group without an override inherits the legacy global duration, or the configured environment default (90 days by default). Central key configuration no longer edits this duration.

New approvals snapshot the owning group, validity duration, and expiry. Later policy or ownership changes do not rewrite existing approvals. Cryptographic signatures require expiry-aware verification policy to enforce the recorded expiry; a valid cryptographic signature alone does not establish current approval validity.

## Verification and deployment

Focused automated tests cover single-owner validation, SQLite migration, ownership transfer authorization, import ownership selection, scoped validity, frozen approval expiry, and frontend forms. PostgreSQL migration triggers and disconnected Harbor publication still require testing in the deployment environment.
