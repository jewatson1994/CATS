# Enterprise CA bundle

Place the approved public certificate chain here before building CATScan.

Recommended file:

```text
host-ca-bundle.crt
```

It may contain two trusted roots and the intermediate, concatenated as PEM
blocks. Never add private keys. The placeholder `.gitkeep` can be removed when
the real bundle is copied in.
