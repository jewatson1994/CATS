# CATSchrödinger security audit

## Architecture found

CATS scanning/publication produced Helm sources and could dispatch a package to a FastAPI validation worker. The worker used mTLS transport, persisted job state, and invoked the existing Kind deployment engine. That engine also served local validation and capability-provider workflows. Security decisions in the remote path did not consistently bind transport identity, inspected resources, actual deployed output, runtime isolation and cleanup ownership. Existing tests primarily used simulated subprocess results, leaving actual Docker/Kind behavior unproved on the development Windows host.

## Findings and remediation

| Severity | Finding / risk | Component | Remediation |
|---|---|---|---|
| HIGH | CA-valid clients were insufficiently distinguished from authorized submitters | server/API | transport-derived leaf SHA256 identity and mandatory explicit allowlist; no trusted identity headers; job ownership |
| HIGH | unsafe workload settings or uninspected Helm execution could cross into privileged Kind nodes | deployment engine | mandatory remote strict policy, allowlisted resources, reject privileged/root/host namespace/mount/capability/token settings, restricted admission, apply exact inspected rendering |
| HIGH | isolation/resource failures could permit execution with ineffective controls | deployment engine | fail closed on internal network, node CPU/memory/PID limits and admission enforcement; offline local image requirement |
| HIGH | hostile input paths, malformed packages or excessive payloads could escape/burden worker | protocol/API/engine | strict schema, normalized relative source paths, bounded source/request/render/files/objects/time/output; generated job IDs and private workspaces |
| MEDIUM | raw subprocess/workload evidence could reveal credentials or attacker-controlled content | worker/client | bounded structured results; raw output withheld; field/rule policy evidence without submitted values |
| MEDIUM | interrupted jobs and ownership-ambiguous cleanup could leak resources or affect unrelated clusters | worker/engine | persisted ownership, recovery, exact names/labels, finally cleanup with separately reported failures |
| MEDIUM | certificate/key/config errors could silently weaken or disable secure operation | server/client | explicit trust material, protected key permissions, no TLS/redirect fallback, validated startup configuration and preflight |
| INFORMATIONAL | Kind orchestration uses privileged nodes and a rootful Docker socket | architecture | dedicated disposable VM documented; remains an architectural authority boundary |

These are design/control classifications, not claims of demonstrated exploit or certification. Consult code/tests for exact supported resource kinds and numerical limits. A submission rejected by sandbox policy is not deployed.

## Architecture after remediation

```text
CATS (configured CA, encrypted client key)
  -- verified HTTPS + client certificate --> validator transport
  -- leaf fingerprint authorization ------> bounded versioned API/job owner
  --> private unique workspace / bounded render + strict policy
  --> host Docker authority (trusted orchestration only)
  --> unique internal network + privileged Kind node with resource limits
  --> restricted namespace / exact approved manifest / nonroot untrusted pods
  --> bounded readiness/evidence --> verified cluster/network/workspace cleanup
  <-- structured sanitized result; cleanup reported independently
```

Untrusted input crosses CATS→API as JSON/file contents, rendering→policy as Kubernetes objects, orchestration→Kind as inspected manifests, and image→kernel as executing code. Images and registries are separate supply-chain boundaries: administrator-controlled provisioning preloads exact images and establishes registry CA trust. Results remain untrusted application evidence; success grants no trust. Client authorization binds jobs so one authorized client cannot inspect/cancel another client's jobs.

## Residual risks and operational obligations

The API/worker process can control the rootful Docker socket and therefore the VM host. Kind nodes are privileged and share the VM kernel; sandbox policy cannot protect against a runtime/kernel/Kind vulnerability or compromised orchestration process. Systemd hardening does not constrain what Docker can launch. Destroy/rebuild this VM after suspicious execution; do not store unrelated secrets there.

Internal Docker networking and disabled image downloads reduce egress, but are not a universal packet firewall or a proof against privileged-node escape. Verify host/forwarding isolation and deny metadata, management/private infrastructure and CATS destinations externally. No configurable registry egress proxy or generic destination allowlist is implemented; use offline preload. Private registries require administrator-installed Docker CA trust.

CPU/memory/PID and package/output limits reduce denial of service, but shared kernel, Docker image storage, filesystem consumption, inode exhaustion and simultaneous activity remain host concerns. Free-space checks and ephemeral-storage accounting are not host filesystem quotas. Use a dedicated volume/VM disk, monitor capacity, rotate persisted completed records and journals, and keep concurrency at one until capacity is measured. Abrupt reboot/runtime failure may leave owned resources; verify recovery and treat cleanup failure as requiring action.

Strict execution intentionally rejects hooks, unsupported resource types and workloads requiring unavailable capabilities. Applying inspected Helm output does not test full Helm release/hook behavior. Offline execution cannot validate external dependencies. SAN, certificate lifetime and authorization rotation require PKI operations; removal of allowlist fingerprints is the immediate application revocation mechanism. Logs are deliberately less rich to prevent secret disclosure.

Host preflight is read-only and does not demonstrate a live cluster lifecycle. Strict isolated gateway networking requires Docker 28+; host-loopback Kubernetes API connectivity with this configuration remains an explicit integration risk until the actual Linux VM passes a Kind lifecycle test. Automated unit/security tests and transport tests are evidence of specified checks, not evidence that an unavailable Linux Docker/Kind integration ran. Run the authenticated, unauthorized, safe-workload, dangerous-workload and cleanup checks in [the setup guide](schrodinger-setup.md) on the actual isolated VM before service use.
