# Helm diagram demo

This chart intentionally contains several rendered workloads and relationships:
frontend, API, worker, PostgreSQL, Redis, an HPA, ingress routes, a CronJob,
configuration, a secret, a service account, RBAC, and persistent storage.

Render it locally:

```text
helm template demo ./scanning-main/examples/helm-diagram-demo > rendered.yaml
```

Then submit the chart or rendered evidence through the CATS scan flow. The
resulting service Overview should expose the chart/image provenance that feeds
the Helm Diagram.

