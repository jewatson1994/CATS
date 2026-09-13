# Remediation candidates

CATS remediation is transactional. A request records the original execution and revision, builds a separate candidate, runs validation, and leaves the ingested source and images unchanged. Candidate states are `queued`, `running`, `review_required`, `validated`, `not_remediable`, and `failed`.

Configuration findings are classified as `AUTO-REMEDIABLE`, `REVIEW REQUIRED`, or `NOT REMEDIABLE`. CATS only applies a deterministic rule when the rendered target resolves to one object and the uploaded source mapping identifies an editable values key, or when the uploaded artifact is a raw Kubernetes manifest. A Helm `# Source:` template marker without a values key is deliberately ambiguous and produces a review proposal.

The candidate archive contains the editable chart or raw manifests plus `remediation-plan.yaml` and `before-after.json`. Each change records the finding/check, severity, source path, original path/value when available, proposed value, reason, timestamp, classification, and remediation job ID. An administrator may designate one saved OCI registry as the remediation staging registry. Service remediation then sends every discovered image through the existing Patch → Scan → Publish worker, captures its immutable manifest digest, and signs that digest when `COSIGN_PRIVATE_KEY` is configured. An image source update is automatic only when publication succeeded and its Helm values mapping is exact; otherwise the published proposal remains in review.

Static validation and deployment validation are distinct. Static validation requires Helm lint/template for chart candidates, YAML parsing, Kubernetes schema validation, image reference checks, source mapping checks, CATS policy validation, Trivy configuration scanning, vulnerability re-scanning when images exist, and expected-resource preservation. An unavailable required tool is a failed static gate rather than an implied pass. Deployment validation remains `NOT RUN` unless `CATS_REMEDIATION_KUBECONFIG` identifies a validation cluster. When configured, CATS creates a job-specific namespace, installs all candidate charts, waits for pods, records the result, and deletes the namespace. CATS never labels a Helm render as functional validation.

Source-producing integrations may include these optional fields in the execution payload:

```yaml
artifact_type: helm
helm_source_files:
  Chart.yaml: |-
    apiVersion: v2
    name: example
    version: 1.0.0
  values.yaml: |-
    security:
      allowPrivilegeEscalation: true
```

Rendered resources may include `_cats_source_mappings`. Exact mappings name `field_path`, `template`, `values_file`, and `values_key` with `ambiguous: false`. Scanner-generated template-only mappings use `ambiguous: true` and never guess a values key.
