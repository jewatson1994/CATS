# Risk Policy and native VEX training

Use a training service and a group you are authorized to manage. Each service has one owning group. Global configuration managers can choose any group; scoped managers see their authorized groups. A service-only configuration grant does not grant group administration.

## Create and preview a profile

1. Open **Administration → Risk Policy**, select the owning group, and open **Risk Profiles**.
2. Enter a descriptive name or start from a saved version in that group.
3. Set minimum scores for Medium, High, and Critical in increasing order. Low starts at zero; scores are capped at 100.
4. Review starting severity scores. Expand evidence and age adjustments only when you need to tune them. EPSS scales added points; KEV sets a minimum. Uncertainty adds points and applies a floor.
5. Review multipliers carefully: 1 retains the score and 0.25 retains 25%. Reductions require sufficiently certain evidence. Decision labels describe human authority; editing labels does not grant permissions.
6. Open **Assessments**, select a service, and preview the draft. Review uncertainty, provenance, evidence freshness, and affected observations. A preview does not assign the profile.
7. Return to **Risk Profiles**, enter the profile name again if needed, and save the reviewed draft as a new version. Assign the reviewed version to the selected group as a separate action. The assignment affects services resolving policy through that group; parent-group inheritance applies where no nearer assignment exists.

Changing groups clears the current editor selection. Preserve your work before switching. Historical versions and assessments remain available; reassess when evidence or policy changes. These scores and human decisions are informational, not publication authorization or compliance overrides.

## Review native VEX separately

Native exclusion is disabled by default and configured in **Administration → General Policy**. Preview its impact before enabling it with the required configuration permission. This control is separate from numeric profile tuning.

Only current trusted Not Affected evidence with an exact applicable identity can exclude an observation. Package, version, distribution and product context matter. Stale, conflicting, missing or ambiguous evidence remains conservative. A CVE appearing in the corpus is not proof that it applies to your package. Mixed findings remain actionable for observations that are not excluded.

Inspect retained evidence and the VEX Excluded view in Services/Raw Findings. Verify identity, source, freshness and disposition. Original scanner rows are retained. Existing POA&Ms and approvals are not automatically rewritten; review them independently.

## Deployment exercise

Confirm portal and workers use the same release and that `risk-worker` runs. For disconnected operation, verify the signed embedded snapshot imported successfully and inspect freshness; no live vendor lookup is required for local evaluation. Initial import can take tens of minutes before readiness.

On test evidence, exercise reassessment, an unmatched package, mixed observations, stale evidence and policy disable/enable. Check pending or failed worker jobs rather than assuming a missing result means clean evidence. The real-container audit found zero applicable positive matches; use controlled fixtures for positive behavior and validate genuine publisher applicability on your own images.

## Upgrade and completion checks

Keep database backups, encryption keys and persistent volumes. Legacy unscoped profiles remain historical records but must be recreated in the intended group and assigned to govern current scoring.

Before completing training, explain the difference between a saved profile and an assignment, identify the service's owning group, distinguish an informational score from native exclusion, and show why an unresolved or stale observation cannot be excluded.

See [native VEX lifecycle](../native-vex-disposition.md), [risk model](../risk-model.md), and [installation and role guides](../../README.md).
