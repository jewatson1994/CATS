# Synthetic Grype test reports

The generator creates 40 synthetic reports for local CATS testing. They use
`CVE-2099-*` identifiers, `example.invalid` references, and explicit
`synthetic: true` metadata. The generated `test-grype-reports/` directory is
intentionally excluded from Git. Do not upload these reports to production.

Generate or regenerate the fixture set:

```powershell
.\.venv\Scripts\python.exe tools\generate_test_grype_reports.py
```

Validate the conversion without sending anything:

```powershell
.\.venv\Scripts\python.exe tools\ingest_test_grype_reports.py --dry-run
```

Ingest all 40 reports into a local portal using the pipeline token from `.env`:

```powershell
$env:PIPELINE_API_TOKEN = "your-local-pipeline-token"
.\.venv\Scripts\python.exe tools\ingest_test_grype_reports.py --url http://localhost:8080
```

The reports represent four scans each for ten services. Findings are varied
between scans so the dashboard exercises active, resolved, and recurring CVE
lifecycle behavior.
