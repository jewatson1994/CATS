# Optional Helm cache

This directory is copied to `/opt/catscan/helm`. Its expected structure is:

```text
cache/
config/
data/
```

The reliable offline approach is to commit or package chart dependencies under
each umbrella chart's `charts/` directory. A Helm repository cache alone does
not guarantee that dependency archives are available without network access.
