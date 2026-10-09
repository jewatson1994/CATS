# Remediation wizard

Service and finding remediation follows six stages. Enable remediation in administration before starting. The existing public Patch workspace is separate.

1. **Plan:** choose Automated or Guided remediation. Automated accepts supported deterministic changes; Guided lets you review decisions.
2. **Review:** inspect proposed image, chart, and configuration changes, the source assessment and version, and items requiring manual review. Unsupported or ambiguous changes remain visible.
3. **Confirm:** approve the selected plan and decisions explicitly. Confirmation binds the job to the source execution and plan. A repeated submission reuses the same confirmation rather than starting duplicate work.
4. **Remediate:** create a retained candidate revision. Monitor image and configuration work, static checks, artifact packaging, and partial results. Remediation does not publish candidate artifacts automatically.
5. **Validate:** request deployment validation of the retained candidate, inspect its progress and evidence, or explicitly skip when optional policy permits. A retry validates the same candidate without applying remediation again.
6. **Deliver:** choose a supported delivery method for the retained artifacts. Publication and downloadable deployment bundles have their own delivery attempts and validation evidence.

## Validation policy

`CATS_REMEDIATION_REQUIRE_VALIDATION=true` is the default. OCI publication requires a `VERIFIED` candidate result bound to the retained artifact digest, service, and source version. A success from another candidate or service version cannot satisfy this requirement.

Set the portal environment variable to `false` only when candidate validation is optional. The operator must still resolve the Validate stage by completing a validation attempt or explicitly choosing Skip. An unavailable validator or an explicit skip permits delivery under optional policy, but does not mark the candidate verified. Failed validation or unresolved validator cleanup always blocks OCI publication, including when validation is optional.

A terminal validation failure or unavailable result completes the Validate stage so the operator can inspect delivery choices and download retained troubleshooting evidence. The report preserves the result and permits validation retries when the retained candidate is eligible. A newly created candidate with validation not yet started remains at Validate.

The candidate-validation setting does not waive final delivery validation. A standard or offline deployment bundle must pass its own mandatory validation before it is available for download. OCI delivery also retains separate validation evidence for its destination-specific content. Static checks, runtime validation, publication, and signing remain distinct outcomes.

## Delivery and permissions

| Action | Required scoped permission |
| --- | --- |
| Create a candidate, validate it, or skip optional validation | `remediation.execute` |
| View reports and progress | `service.view` |
| Download candidate evidence or an eligible bundle | `service.export` |
| Publish retained artifacts to OCI | `artifact.publish` |
| Sign artifacts when signing is required | `artifact.sign` |

Administrator and Cybersecurity system roles include `artifact.publish`. Service Manager does not receive it automatically. Assign publication permission through the existing role controls when appropriate. Publication also enforces validation policy and configured signing requirements.

Delivery choices reflect the retained artifact inventory. A candidate download contains retained work and evidence for inspection. OCI requires publishable image or chart artifacts. Standard and offline bundles require compatible deployment content; offline delivery additionally needs its complete image and dependency inventory. Unsupported formats are omitted. Available formats can still be disabled by permissions or policy, with a reason shown.

Downloading a candidate for troubleshooting does not claim that it deploys successfully. Validation and delivery retries reuse retained artifacts; rerunning remediation creates a separate revision. Ingest a new authoritative assessment after deployment to update service findings and governance evidence.

## Existing jobs and deployment

New jobs store workflow version, approved plan, decisions, and capability metadata in existing JSON fields. No database schema migration is required for this workflow. Existing retained jobs and reports remain accessible. Legacy terminal jobs may treat their historical not-verified state as resolved for navigation, but still need digest- and service-bound verified evidence before OCI publication when validation is required.

Retrying candidate creation preserves the confirmed source and approved decisions and creates a new revision that must pass through Validate and Deliver again. Older jobs without an approved plan require starting the wizard and confirming a new plan; they cannot bypass confirmation through Retry.

Rebuild and deploy the portal to deliver the updated interface and backend together. Configure `CATS_REMEDIATION_REQUIRE_VALIDATION` in the portal environment, and continue using existing patch-worker, registry, signing, validator, and retention settings. The workflow does not establish live registry or validator connectivity; those depend on the deployed services and their configured trust.

Before rollback, stop new remediation submissions and let candidate, validation, and delivery operations finish. Restore the previous portal image and configuration together while preserving database and artifact volumes. There is no schema downgrade, but the earlier interface does not enforce this wizard's confirmation and delivery sequence; keep new submissions disabled until the intended workflow is restored.

See also [remediation pipeline and retained candidates](../portal/docs/remediation-pipeline.md), [disconnected delivery limits](schrodinger-deliveries.md), and [signing](../portal/SIGNING.md).
