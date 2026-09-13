# Optional pinned tool archives

For a disconnected CATScan build, place these official release archives here:

- `trivy_0.69.3_Linux-64bit.tar.gz`
- `dockle_0.4.15_Linux-64bit.tar.gz`
- `helm-v4.2.3-linux-amd64.tar.gz`

The Docker build verifies each archive against the SHA-256 value pinned in the
Dockerfile. Do not replace an archive without updating its version and reviewed
checksum together.
