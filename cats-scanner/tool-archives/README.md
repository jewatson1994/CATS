# Optional pinned tool archives

For a disconnected CATScan build, place these official release archives here:

- `trivy_0.69.3_Linux-64bit.tar.gz`
- `dockle_0.4.15_Linux-64bit.tar.gz`
- `helm-v4.2.3-linux-amd64.tar.gz`
- `kind-v0.33.0-linux-amd64`
- `kubectl-v1.37.0-linux-amd64`

The Docker build verifies each archive against the SHA-256 value pinned in the
Dockerfile. Do not replace an archive without updating its version and reviewed
checksum together.

Built-in MetalLB 0.16.1 also accepts these offline build inputs:

- `metallb-native-v0.16.1.yaml`
- `metallb-controller-v0.16.1-linux-amd64.tar`
- `metallb-speaker-v0.16.1-linux-amd64.tar`

Built-in ingress-nginx 1.15.1 accepts these offline build inputs:

- `ingress-nginx-kind-v1.15.1.yaml`
- `ingress-nginx-controller-v1.15.1-linux-amd64.tar`
- `ingress-nginx-kube-webhook-certgen-v1.6.9-linux-amd64.tar`

The build scripts pin the upstream manifests and image/config digests and check
each archive layer. See `cats-scanner/README.md` for details. The resulting
bundle is included in the exported CATS image; validators need no registry or
upstream access for provider dependencies.
