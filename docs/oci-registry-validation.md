# Independent Distribution registry validation

On 2026-10-19, the production `RegistryClient` passed interoperability checks against a real, isolated Docker Distribution 2.8.3 registry, separate from the Harbor fixture. The image was pinned to `registry@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373`.

The fixture bound only `127.0.0.1:18543`, generated a short-lived localhost TLS certificate and random Basic-auth password, uploaded a valid OCI image with a tar layer, and checked:

- Custom-CA TLS and authenticated pulls.
- Exact original manifest bytes through both tag and digest lookup.
- Streamed layer retrieval with SHA-256 verification (10,240-byte tar).
- Rejection of anonymous access, a wrong password, and an untrusted CA.

All checks passed. The manifest digest was `sha256:5fa9e06f052b2d4ee5d28f7d895d9166f6f2eadd7f0fea5d8bf0cce75c9b61ca`. This validates the actual transport against Distribution's TLS/Basic protocol path; current CATS authorization and Harbor's Bearer protocol have separate tests.

Run `python tests/registry/smoke_distribution.py` from the repository root with project Python dependencies and Docker available. It uses pinned registry and password-file-helper images, creates a uniquely named isolated container, and removes only that container in a `finally` block. Port 18543 must be free. It does not modify existing services or push to remote registries. Temporary certificates, password hashes, cache, and a nonsecret results JSON remain under `.test-temp/distribution-local`; they are local test artifacts and must not be committed. The generated password is never printed or written to the results report.
