# Bundled Grype database

This directory is a build context, not a source-controlled vulnerability
snapshot. On a connected release host, run:

```bash
../scripts/prepare-grype-db.sh
```

The script populates the current Grype v6 cache and validates its
`vulnerability.db` and metadata. The scanner Dockerfile can also populate the
cache directly during a connected build. Do not treat `.gitkeep` as a valid
database; release-image validation requires real database content.
