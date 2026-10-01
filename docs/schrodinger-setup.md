# CATSchrödinger's setup

Deployment validation executes untrusted code. Use a dedicated disposable Linux VM, without production credentials, unrelated workloads, cloud instance credentials, or access to management networks. A VERIFIED result means deployability under sandbox restrictions, never trust or security approval. Read [the audit](schrodinger-security-audit.md) before exposing the service.

## 1. Requirements and network

Reference installation: Ubuntu 24.04 LTS amd64, systemd, Python 3.12, rootful Docker Engine, Kind, kubectl and Helm. Budget at least 8 vCPU, 16 GiB RAM and 60 GiB dedicated disk for one job; larger images need more disk. These are operator sizing recommendations, not tested minimums. Rootless Docker/Kind is not certified by this implementation: verify cgroups, internal network isolation and the full lifecycle before considering another runtime.

| Source | Destination | Port/protocol | Purpose |
|---|---|---|---|
| CATS host | validator FQDN | 8443/TCP HTTPS (configurable) | mTLS API and health |
| administrator | VM | 22/TCP SSH if used | restricted management |
| VM administrator/runtime | approved package and image sources | 443/TCP HTTPS | provisioning and preloading only |
| VM | organization DNS | 53/UDP and TCP if used | provisioning/name resolution |
| validator process | Docker | local Unix socket | Kind orchestration; never expose TCP Docker |
| validator process | ephemeral Kubernetes API | dynamically allocated loopback TCP | local job control |
| submitted pods | external networks | deny | offline validation |

Restrict inbound 8443 to CATS addresses. Apply external VM firewall/security-group egress denial to management, private infrastructure, link-local/metadata and CATS networks. Docker manipulates host firewall rules: do not assume an ordinary UFW rule protects forwarded containers. Strict execution requires **Docker Engine 28+**, a per-job internal bridge with IPv4 gateway mode `isolated`, IPv6 disabled, and verified node attachment only to that owned network. Older engines fail closed. **Kind's host-loopback Kubernetes API must be proven reachable with this isolated networking on your VM; this combination has not been live-validated on the Windows development host. Do not treat this guide or unit tests as production-readiness certification.** There is no generic registry destination allowlist/proxy implementation. Keep offline validation enabled and preload approved images.

## 2. Service account and prerequisites

Run the following as an administrator with sudo. Deploy the reviewed repository to `/opt/cats` (owned by root; writable only by administrators), including `portal` and `scripts`.

```sh
sudo apt-get update
sudo apt-get install -y ca-certificates curl openssl python3 python3-venv
sudo useradd --system --create-home --home-dir /var/lib/cats-validator --shell /usr/sbin/nologin cats-validator
sudo install -d -o cats-validator -g cats-validator -m 0700 /var/lib/cats-validator /var/lib/cats-validator/workspaces
sudo install -d -o root -g cats-validator -m 0750 /etc/cats-validator /etc/cats-validator/tls
sudo python3 -m venv /opt/cats/.venv
sudo /opt/cats/.venv/bin/pip install -r /opt/cats/portal/requirements.txt
```

Install Docker Engine using the [official Ubuntu apt repository procedure](https://docs.docker.com/engine/install/ubuntu/), including its signed repository key; pin an organization-approved available package version. Do not run a downloaded installation script. Then:

```sh
sudo systemctl enable --now docker
sudo usermod -aG docker cats-validator
sudo -u cats-validator docker info
```

Docker group membership grants **host-root authority** through the rootful socket ([Docker documentation](https://docs.docker.com/engine/install/linux-postinstall/)). The API and worker share this authority. A dedicated Unix user and systemd hardening do not remove it. Kind nodes themselves require privileged container execution; submitted pods are denied privileged settings and host mounts. Never mount the socket into submitted workloads or deploy this beside CATS on a shared host.

## 3. Kind, kubectl, Helm and offline images

Select an approved Kind release and a matching `kindest/node` image digest from its [release instructions](https://kind.sigs.k8s.io/docs/user/quick-start/). Install the downloaded binary after verifying the release checksum; use the matching Kubernetes minor for kubectl. Install Helm 3 using its signed release/checksum instructions at [Helm installation](https://helm.sh/docs/intro/install/). Record the binary versions and verified checksums in the VM inventory. Example kubectl installation, with your approved version substituted:

```sh
KUBECTL_VERSION='<APPROVED_KUBERNETES_VERSION>'
curl -fLO "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl"
curl -fLO "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl.sha256"
printf '%s  kubectl\n' "$(cat kubectl.sha256)" | sha256sum --check
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
kind version
kubectl version --client
helm version --short
```

Do not treat the repository's node-image default as an externally verified release. Explicitly configure a genuine approved digest available in your registry and preload it. During the controlled provisioning window:

```sh
sudo -u cats-validator docker pull '<APPROVED_KIND_NODE_IMAGE_WITH_SHA256_DIGEST>'
sudo -u cats-validator docker pull '<APPROVED_NONROOT_WORKLOAD_IMAGE_WITH_SHA256_DIGEST>'
```

Alternatively load trusted administrator-provided OCI/Docker archives with `docker load --input <ARCHIVE>`. Configure private registry CA trust in Docker according to the approved registry's FQDN/port; no insecure registry or TLS bypass. Registry secrets belong to provisioning only. Close provisioning egress afterward. All actual submitted image references must already exist locally; requests cannot download arbitrary URLs.

## 4. Certificates and authorization

Use organization-approved PKI. Issue the server certificate with DNS SAN `<SCHRODINGER_FQDN>` and serverAuth EKU. Issue each CATS client certificate with clientAuth EKU. Use separate client/server trust anchors where possible. Server certificate PEM should include required intermediate certificates. CATS must trust the explicit server CA, and the validator must trust the explicit client CA. Install on the VM:

```sh
sudo install -o cats-validator -g cats-validator -m 0600 <SERVER_KEY_PATH> /etc/cats-validator/tls/server-key.pem
sudo install -o root -g cats-validator -m 0640 <SERVER_CERT_PATH> /etc/cats-validator/tls/server-cert.pem
sudo install -o root -g cats-validator -m 0640 <CLIENT_CA_PATH> /etc/cats-validator/tls/client-ca.pem
openssl x509 -in <CATS_CLIENT_CERT_PATH> -outform DER | openssl dgst -sha256
```

Copy only the final 64 hexadecimal characters from the fingerprint command. `CATS_VALIDATOR_CLIENT_FINGERPRINTS` is a mandatory comma-separated allowlist of SHA256 hashes of the **DER leaf client certificate**, not CA or public-key hashes. Valid CA signatures authenticate; the allowlist authorizes. Add the new fingerprint before rotating the CATS client certificate, then remove the old fingerprint. Protect the CATS private key; do not commit keys, put them in URLs, or paste them into logs. Certificate renewal/revocation is an operational responsibility; rotate/remove fingerprints for revocation.

## 5. Configure and install

Create `/etc/cats-validator/validator.env`, root-owned mode 0640, group cats-validator. Replace placeholders; systemd EnvironmentFile does not perform shell substitutions:

```ini
CATS_VALIDATOR_LISTEN=0.0.0.0
CATS_VALIDATOR_PORT=8443
CATS_VALIDATOR_SERVER_CERT=/etc/cats-validator/tls/server-cert.pem
CATS_VALIDATOR_SERVER_KEY=/etc/cats-validator/tls/server-key.pem
CATS_VALIDATOR_CLIENT_CA=/etc/cats-validator/tls/client-ca.pem
CATS_VALIDATOR_CLIENT_FINGERPRINTS=<CLIENT_LEAF_SHA256_HEX>
CATS_VALIDATOR_STATE_DIR=/var/lib/cats-validator
CATS_VALIDATOR_MAX_JOBS=1
CATS_VALIDATOR_MAX_REQUEST_BYTES=16777216
CATS_VALIDATOR_MAX_OUTPUT_BYTES=1048576
CATS_VALIDATOR_MAX_TIMEOUT=600
CATS_VALIDATOR_MAX_RECORDS=1000
CATS_VALIDATOR_MIN_DISK_BYTES=5368709120
CATS_DEPLOYMENT_KIND_NODE_IMAGE=<APPROVED_KIND_NODE_IMAGE_WITH_SHA256_DIGEST>
CATS_DEPLOYMENT_ALLOW_NETWORK_EGRESS=false
CATS_DEPLOYMENT_REQUIRE_LOCAL_IMAGES=true
CATS_DEPLOYMENT_API_ADDRESS=127.0.0.1
CATS_DEPLOYMENT_NODE_CPUS=4
CATS_DEPLOYMENT_NODE_MEMORY=8g
CATS_DEPLOYMENT_NODE_PIDS=2048
```

Default state is `/tmp/cats-validator`; dedicated `/var/lib/cats-validator` preserves recovery records across reboot. The API forces strict policy and uses `<state>/workspaces`; do not use the alternate local permissive engine as the remote service. Limits also include source/render/object/pod/resource bounds in `ValidationConfig`. Disk free-space checks are not filesystem quotas: dedicate and monitor the VM disk, rotate completed records/logs, and cap image storage operationally.

Install `/etc/systemd/system/cats-validator.service`:

```ini
[Unit]
Description=CATSchrodinger isolated deployment validator
After=network-online.target docker.service
Requires=docker.service

[Service]
User=cats-validator
Group=cats-validator
SupplementaryGroups=docker
WorkingDirectory=/opt/cats/portal
EnvironmentFile=/etc/cats-validator/validator.env
ExecStart=/opt/cats/.venv/bin/python /opt/cats/portal/validator_server.py
Restart=on-failure
RestartSec=5
TimeoutStopSec=90
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/cats-validator
PrivateTmp=yes
RestrictSUIDSGID=yes
TasksMax=4096
LimitNOFILE=8192

[Install]
WantedBy=multi-user.target
```

PrivateTmp isolates process temp files, not Docker-host mounts. Do not add PrivateNetwork: the worker needs the host's loopback Kubernetes API. systemd process limits do not constrain containers created by the separate Docker daemon. Start and inspect:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now cats-validator
sudo systemctl status cats-validator --no-pager
sudo journalctl -u cats-validator -n 50 --no-pager
```

Run read-only preflight as the service user with the environment loaded (the administrator controls this file):

```sh
sudo -u cats-validator sh -c 'set -a; . /etc/cats-validator/validator.env; set +a; /opt/cats/.venv/bin/python /opt/cats/scripts/schrodinger-preflight.py'
```

READY means basic local prerequisites passed. WARNs require operator review; this does not create a Kind cluster or prove isolation, TLS chain/SAN, client authorization, or a successful workload lifecycle.

## 6. Verify transport and connect CATS

From the CATS host, use paths to its client key/certificate and trusted server CA:

```sh
# Must fail the TLS handshake (no client certificate).
curl --fail --cacert <SERVER_CA_PATH> https://<SCHRODINGER_FQDN>:8443/health
# Must return authenticated JSON, compatible schema, and ready=true.
curl --fail --cacert <SERVER_CA_PATH> --cert <CATS_CLIENT_CERT_PATH> --key <CATS_CLIENT_KEY_PATH> https://<SCHRODINGER_FQDN>:8443/health
```

Repeat with a CA-valid client certificate absent from the allowlist: HTTP 403 is required. Never add `-k`. In CATS, open cog → Administration → Settings (global scope) → CATSchrödinger validator: save endpoint `https://<SCHRODINGER_FQDN>:8443`, server CA PEM, CATS client certificate PEM and client private key PEM, then use the connection test. The actual persisted setting is `validator_configuration`, with `endpoint`, `ca_certificate`, `client_certificate`, and encrypted `client_key`; these are PEM contents, not host filenames. Client HTTP calls have a fixed 30-second per-request timeout; package timeout defaults to 600 seconds, bounded by the server, plus polling/cleanup grace. Clearing the endpoint disables remote selection. Remote unavailability must be reported without blocking unrelated scanning.

## 7. Safe lifecycle and policy-rejection tests

Use a small Helm chart with no hooks/dependencies and a digest-pinned, preloaded nonroot image. Its Pod template must explicitly set:

```yaml
spec:
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: smoke
      image: <APPROVED_NONROOT_WORKLOAD_IMAGE_WITH_SHA256_DIGEST>
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: [ALL]
      resources:
        requests: {cpu: 10m, memory: 16Mi}
        limits: {cpu: 100m, memory: 64Mi}
```

Use an image whose default process stays running without network access. Submit the chart through the normal CATS Publish Service deployment-validation flow. Observe CATS → mTLS API → unique workspace/Kind cluster → approved rendered manifests → readiness/result → cleanup. Expect `VERIFIED`, `outcome=SUCCESS`, `cleanup_status=COMPLETE`. Strict remote execution templates Helm once and applies that exact inspected output; Helm hooks, cluster-scoped controllers/CRDs and other unsupported behavior are rejected, so this is not full Helm installation semantics.

Repeat with `securityContext.privileged: true` in the container: expect `POLICY_REJECTED` / `SECURITY_POLICY_VIOLATION`, field/rule evidence and no workload execution. Test an unavailable local image, invalid certificate and short timeout separately. A policy rejection or unavailable infrastructure does not establish that the application fails on production Kubernetes.

For a repeatable API smoke test, run this on the CATS host with Python 3 and curl. Replace every placeholder. The approved image must stay running by default as UID 65532, without network access, and already be loaded on the VM. This builds two tiny chart packages, submits them over mTLS and polls server-generated IDs. Only summary fields are printed; certificate/key contents are never read into package JSON. Use the same certificate for submission and polling.

```sh
export SCHRODINGER_URL='https://<SCHRODINGER_FQDN>:8443'
export SERVER_CA='<SERVER_CA_PATH>'
export CLIENT_CERT='<CATS_CLIENT_CERT_PATH>'
export CLIENT_KEY='<CATS_CLIENT_KEY_PATH>'
export SMOKE_IMAGE='<APPROVED_NONROOT_WORKLOAD_IMAGE_WITH_SHA256_DIGEST>'
umask 077
SMOKE_DIR=$(mktemp -d)
export SMOKE_DIR
python3 - <<'PY'
import json, os, pathlib, re
image = os.environ['SMOKE_IMAGE']
assert re.fullmatch(r'[A-Za-z0-9._:/-]+@sha256:[0-9a-f]{64}', image), 'Use a digest-pinned approved image'
chart = 'apiVersion: v2\nname: cats-smoke\nversion: 0.1.0\n'
pod = '''apiVersion: v1
kind: Pod
metadata:
  name: cats-smoke
spec:
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: smoke
      image: IMAGE
      securityContext:
        allowPrivilegeEscalation: false
        privileged: false
        capabilities:
          drop: [ALL]
      resources:
        requests: {cpu: 10m, memory: 16Mi}
        limits: {cpu: 100m, memory: 64Mi}
'''.replace('IMAGE', image)
for name, template in [('safe', pod), ('dangerous', pod.replace('privileged: false', 'privileged: true'))]:
    package = {'schema_version': 'cats.validation/v1',
        'manifest': {'service_key': 'cats-smoke-' + name, 'timeout_seconds': 600,
                     'referenced_images': [image], 'required_capabilities': []},
        'artifact': {'source_files': {'Chart.yaml': chart, 'templates/pod.yaml': template},
                     'values_files': [], 'declared_resources': [], 'artifact_type': 'helm'}}
    pathlib.Path(os.environ['SMOKE_DIR'], name + '.json').write_text(json.dumps(package))
PY
for CASE in safe dangerous; do
  curl --fail --silent --show-error --max-time 30 --cacert "$SERVER_CA" \
    --cert "$CLIENT_CERT" --key "$CLIENT_KEY" -H 'Content-Type: application/json' \
    --data-binary "@$SMOKE_DIR/$CASE.json" "$SCHRODINGER_URL/api/v1/validations" \
    -o "$SMOKE_DIR/submitted.json" || break
  JOB_ID=$(python3 - "$SMOKE_DIR/submitted.json" <<'PY'
import json, re, sys
value = json.load(open(sys.argv[1]))['validation_id']
assert re.fullmatch('[0-9a-f]{32}', value), 'Invalid job ID'
print(value)
PY
  ) || break
  export CASE JOB_ID
  python3 - <<'PY'
import json, os, pathlib, subprocess, time
deadline = time.monotonic() + 780
destination = pathlib.Path(os.environ['SMOKE_DIR'], 'state.json')
while time.monotonic() < deadline:
    subprocess.run(['curl', '--fail', '--silent', '--show-error', '--max-time', '30',
        '--cacert', os.environ['SERVER_CA'], '--cert', os.environ['CLIENT_CERT'],
        '--key', os.environ['CLIENT_KEY'], os.environ['SCHRODINGER_URL'] +
        '/api/v1/validations/' + os.environ['JOB_ID'], '-o', str(destination)], check=True)
    state = json.loads(destination.read_text())
    if state['status'] not in ('QUEUED', 'RUNNING'):
        result = state.get('result') or {}
        print(json.dumps({'case': os.environ['CASE'], 'job': os.environ['JOB_ID'],
            'status': state['status'], 'outcome': result.get('outcome'),
            'reason_category': result.get('reason_category'),
            'cleanup_status': result.get('cleanup_status'),
            'policy_violations': result.get('policy_violations', [])}))
        expected = 'SUCCESS' if os.environ['CASE'] == 'safe' else 'POLICY_REJECTED'
        assert result.get('outcome') == expected, 'Unexpected outcome; inspect configuration and policy'
        assert result.get('cleanup_status') in ('COMPLETE', 'NOT_REQUIRED'), 'Cleanup requires operator action'
        break
    time.sleep(2)
else:
    raise SystemExit('Polling timed out; inspect job and cleanup on VM')
PY
  [ "$?" -eq 0 ] || break
done
# Inspect VM cleanup with the commands below; retain this private test directory
# only if needed for investigation. It contains test packages/results, not keys.
printf 'Private smoke-test directory: %s\n' "$SMOKE_DIR"
```

Before/after tests, inventory as the service user:

```sh
sudo -u cats-validator kind get clusters
sudo -u cats-validator docker ps -a --filter label=io.x-k8s.kind.cluster
sudo -u cats-validator docker network ls --filter label=cats.deployment-validation=true
sudo -u cats-validator find /var/lib/cats-validator/workspaces -mindepth 1 -maxdepth 1 -type d
```

No job cluster/network/workspace should remain after terminal completion. JSON job records intentionally persist; reaching `CATS_VALIDATOR_MAX_RECORDS` rejects new submissions until an administrator archives completed records. Cleanup failure is distinct from deployment success: do not accept `VERIFIED` with `cleanup_status=FAILED` as an operationally complete run. Stop admissions, inspect the recorded job ownership and exact cluster/network, and remove only proven owned resources; never use broad Docker prune. A missing or incorrect network ownership label conservatively fails recovery rather than deleting a potentially foreign cluster. After forced worker restart, inspect recovery result and inventory again. A VM destroyed mid-write or runtime unavailable during cleanup can require administrator recovery.

## 8. Troubleshooting

| Symptom | Check | Remediation |
|---|---|---|
| TLS handshake/hostname failure | `openssl x509 -in <SERVER_CERT> -noout -dates -ext subjectAltName` | fix SAN, chain, expiry, clock or explicit CA; never bypass |
| HTTP 403 with valid client | recompute leaf DER SHA256; inspect allowlist | authorize intended fingerprint and restart |
| registry certificate error | Docker daemon journal and approved CA directory | install approved registry CA; preload images |
| Kind/runtime failure | service-user `docker info`, `kind version`, journal | fix Docker access, compatible node image/cgroups/disk |
| image pull failure | service-user `docker image inspect <EXACT_IMAGE>` | preload exact digest reference; keep offline policy |
| Helm/policy failure | policy field evidence, `helm template` on trusted operator copy | fix chart and explicit pod controls; unsupported hooks cannot run |
| timeout | result phase, disk/memory and image availability | fix workload/provisioning; increase bounded timeout only deliberately |
| cleanup failure | exact job record plus inventories above | stop submissions; recover only owned resources or rebuild disposable VM |
| permission/startup failure | preflight as service user; journal | fix 0600 key, 0700 state, config bounds and root-owned deployment |

