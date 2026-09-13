# Optional Trivy cache

This directory is copied to `/opt/catscan/trivy-cache` in the CATScan image.
For offline vulnerability scanning, place the reviewed Trivy DB files at:

```text
db/trivy.db
db/metadata.json
```

Configuration scans do not require those files. CATScan uses the checks bundle
embedded in the pinned Trivy binary when `catscan-trivy-config` is used.
