# Trusted CA and package repository policies

CATS administrators can configure the trust and package-source settings used by
container patch jobs from **Administration → Configuration**. These settings are
global policy; they are not registry credentials and are not copied into scan
history.

## Trusted CA certificates

1. Open **Administration → Configuration**.
2. In **Trusted CA certificates**, upload a PEM-encoded root or intermediate
   certificate, or a PEM bundle containing multiple `BEGIN CERTIFICATE` /
   `END CERTIFICATE` blocks. Private keys and other non-certificate content are
   rejected.
3. Save it. CATS validates every X.509 certificate and shows each one
   individually with only non-secret metadata (subject, issuer, validity, type,
   and SHA-256 fingerprint). Duplicate fingerprints are ignored.
4. Remove a certificate by its fingerprint when it is no longer trusted.

The worker's normal public CA bundle is always used as secure bootstrap trust.
Configured CATS roots/intermediates are added in an ephemeral bundle. CATS puts
that trust in a short-lived derivative of the target before Copa starts, so the
first `apk`, `apt`, `dnf`, `microdnf`, or `yum` HTTPS request validates public
and configured private PKI. TLS verification remains enabled.

After patching, CATS removes its private-CA anchor and regenerates the target's
normal CA store before materializing output. Temporary bundles, derivative
images, and the isolated Docker authentication directory are removed on success
or failure. Certificate contents are not written to job state or logs.

## Package repository policies

The built-in OS definitions select the package manager from the image's
`/etc/os-release` file:

| OS family | Package manager |
| --- | --- |
| Ubuntu, Debian | apt |
| RHEL, Rocky Linux, AlmaLinux, CentOS, Fedora | dnf |
| Alpine | apk |

For an OS family, choose **Default** to use the repositories already present in
the image. Choose **Custom** and provide an HTTP(S) mirror URL to make that
mirror authoritative for the Copa patch operation. CATS tests the URL from the
portal before saving when requested. Custom policies expose two independent,
secure-by-default controls: **Verify repository TLS certificates** and **Verify
package signatures**. Clearing either checkbox is an administrative exception
shown in the policy table and audit event.

RPM mirror policies map those controls to DNF/YUM repository-local `sslverify=1`
and `gpgcheck=1` (or `0` when explicitly disabled). Packages must be signed by
a key already trusted in the target image when checking is enabled; CATS does
not import repository signing keys from a URL.

APT uses a repository-local `Acquire::https::Verify-Peer/Verify-Host` override
only in the temporary mirror derivative when TLS checking is disabled. Package
checking disabled is represented by `[trusted=yes]` on the configured `deb`
source, without broad `AllowUnauthenticated` behavior. Alpine uses native `apk`
behavior by default; an exception adds only `--no-check-certificate` and/or
`--allow-untrusted` through a job-local wrapper in the temporary derivative.
The wrapper is removed before output; `--allow-untrusted` is the explicit
package-signature exception.

During patching CATS creates a short-lived derivative image, moves the original
repository files aside, installs the configured repository file, and runs Copa
against that derivative. After Copa completes, the original repository files are
restored before the patched image is scanned and exported. Mirror configuration
does not leak into the resulting image.

Each job uses unique marker paths. CA cleanup backs up and restores pre-existing
bundle, anchor, and `cert.pem` artifacts, including same-name collisions, so
unrelated source CAs remain trusted. `verify_tls=false` does not require a
configured custom CA and does not alter the source trust store by itself.

## Canonical patched artifact

Copa's configured Docker loader places the BuildKit result in the worker's
Docker daemon. CATS gives it a job-unique local tag and runs `docker save` once.
That Docker archive is structurally validated and becomes the canonical patched
artifact. CATS proves the archive can be loaded by Docker, materializes the
canonical image filesystem, and scans it explicitly as `dir:<path>`. This avoids
provider guessing, a registry round trip, and daemon-specific archive layer
representations during the post-patch scan.

Download mode returns that exact archive. Push mode tags the exact job-unique
daemon image from which the validated archive was saved and pushes it only after
the filesystem scan succeeds. A registry is an optional output destination, not
a validation prerequisite.

Images that do not expose a supported OS/package manager continue through the
normal Grype/Copa workflow without a repository override. If a custom OS is
needed, administrators can add an identifier matching `ID` or `ID_LIKE` in
`/etc/os-release`, its display name, and one of `apt`, `dnf`, or `apk`.

## Deployment notes

The patch worker needs access to the Docker/BuildKit runtime and to the selected
package mirror. In a disconnected environment, make the mirror reachable from
the worker and add its issuing CA under Trusted CA certificates. The all-in-one
image includes Copa and verifies that it is available at startup/build time.

Registry credentials are selected from centrally managed registry configuration
and passed only through the job process environment. They are never stored in
job metadata, reports, logs, or artifacts.
