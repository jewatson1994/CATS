# Managed validator readiness completion report

Repository: Cyber Hygiene. Branch: feature/hq-managed-validator-provisioning. No commit, push, deployment, or VM modification.

1. **Exact disabling condition:** The supplied screenshot explicitly shows installation payload unavailable. Therefore `payload.available === true` was false, making `provisionAllowed` false. This is established from the screenshot and code, not a live HQ inspection.
2. **supported_with_warnings:** Already accepted when warnings were acknowledged. The new explicit model preserves this and rejects failed hard checks.
3. **Test Connection state:** Authenticated preflight was already persisted on the validator. No evidence demonstrated it being lost in this case. The computed backend readiness now exposes it explicitly.
4. **Credential clearing/re-entry:** Clearing secrets does not clear durable preflight. Readiness now tracks only temporary credential presence booleans; re-entry restores that item without repeating the connection test. No password or private key is stored in React state or durable readiness.
5. **Upgrade confirmation:** The old expression gated only Upgrade; it did not gate Provision. The checkbox is now rendered only for Upgrade, eliminating the confusing visible confirmation in the screenshot.
6. **Payload readiness:** Yes, the evidenced actual blocker. The required trusted offline payload gate remains enforced; an Ubuntu 22.04 amd64 host cannot use a 24.04-only payload.
7. **Previous button logic:**

   ```ts
   provisionAllowed = !!selected?.ssh_fingerprint && !!preflight && !unsupported
     && (!warningList.length || warningsAccepted)
     && payload.available === true && matchingPayload;
   disabled = busy || !provisionAllowed
     || !permitted(operation === 'upgrade' ? 'upgrade' : 'provision')
     || (operation === 'upgrade' && !upgradeConfirmed);
   // unsupported: status includes 'unsupported', or supported === false.
   // matchingPayload: no platforms list, or a matching OS/version/architecture entry.
   ```

8. **New button logic:** `disabled={!readiness.ready}`, where `ready = checks.every(check => check.ready)`. Submit also guards readiness. Backend durable failures can block the frontend; they cannot override missing temporary credentials or acknowledgments.
9. **Model:** Explicit checks cover trusted fingerprint, authenticated connection, supported hard preflight, warnings, temporary authentication, required sudo credentials, API port, verified compatible payload, Upgrade-only confirmation, permission, and in-progress operation. Backend checks are computed from retained evidence; fresh payload validation remains enforced for provisioning. Payload inventory caching avoids rehashing all assets on every detail poll.
10. **Visible UI:** Rounded panels, themed buttons/status badges, host fact cards with GiB units, grouped pass/block checks, readable warnings, inline checkboxes, readiness checklist, and concrete blocking reasons immediately below the operation button. Raw JSON remains available in collapsed technical details. Empty evidence reads “Not recorded.”
11. **Frontend files:** `portal/frontend/src/features/validators.tsx`, `validators.css`, `validator-readiness.ts`, `validators.test.tsx`, and `validator-readiness.test.ts`.
12. **Backend files:** `portal/app/validator_management.py`, `portal/app/validator_bootstrap.py`, and `portal/tests/test_validator_provisioning_readiness.py`.
13. **Tests added/updated:** 25 pure readiness cases and 15 UI cases, plus backend readiness coverage. Includes the exact DRAFT Ubuntu 22.04 warning-acknowledged/password/sudo/verified-payload state, Upgrade confirmation, missing blockers, credential clearing/re-entry and refresh, and asynchronous failure/retry. Passwordless sudo detection invalidates cached sudo credentials before probing.
14. **Results:** Full frontend suite: 157 passed across 27 files. Focused backend readiness/bootstrap/management suite: 59 passed. These are automated local tests; the real VM acceptance test has not been run.
15. **Build/type check:** Production frontend build, TypeScript check, and scoped frontend lint passed. Build retains the existing bundle-size warning and runtime-resolved `/static/app.css` notice. Visual review used mock data matching the supplied Ubuntu 22.04 host; it did not contact the VM.
16. **Migration:** None. Readiness is computed from existing retained data; the sudo requirement is an additional preflight fact.
17. **Same-validator reload:** Trusted fingerprint and authenticated preflight remain. Warning acknowledgment and temporary credentials must be re-entered. If the trusted matching payload remains unavailable, the button stays disabled with an explicit Ubuntu 22.04 amd64 payload reason. With payload available, acknowledged warnings, credentials present, and other checks passing, DRAFT Provision is enabled with Upgrade confirmation false. Missing Docker is expected and does not block bootstrap.
18. **Exact next step:** Rebuild/redeploy HQ, configure its complete verified offline Ubuntu 22.04 amd64 installation payload and trusted manifest SHA256 using `docs/managed-validator-payload.md`, then reload and Manage CATSchrodinger-Dev-01 (172.22.1.140). Acknowledge retained warnings, re-enter temporary password and required sudo password, select Provision Validator / Retry, and provision once all checklist items are ready. Do not select Upgrade or preinstall tools on the VM to work around readiness. Rebuild alone will not supply the missing payload.

Stopped after implementation and verification as requested.
