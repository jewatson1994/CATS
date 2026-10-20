# Expanded embedded intelligence acceptance evidence

These artifacts accompany [the release report](../../embedded-intelligence-expanded-report.md). They are local measurements, not claims about a production deployment.

- `startup.json`: normal application entrypoint cold-import timing and memory samples. The earlier cold-import image and final hardened image have identical signed intelligence payloads but different application code; their results are attributed separately.
- `environment.json`: Docker, PostgreSQL, resource limits and network isolation; the host was shared with other local tasks.
- `expanded-acceptance.json`: exact corpus counts, current freshness preconditions, real scoped lookups, storage/indexes, unchanged verification and outbound guard results on the cold-import image.
- `baseline-acceptance.json`: retained prior-release verification, unchanged timings and database size after the same-payload sequence upgrade. The historical 600.28-second startup and prior image size come from the release report at commit `78a9012`; its cold-import memory was not measured.
- `baseline-coverage.json`: the same exact counting function against the prior release database, at the same freshness evaluation time. Read-only; its retained same-payload upgrade does not duplicate evidence.
- `final-image.json` and `final-smoke.json`: final normal-image repeat startup and bounded runtime checks against the imported database. Handler timings exclude HTTP transport and authentication middleware. The worker context helper is tested with real evidence; the smoke deliberately does not persist full assessment refreshes. The focused automated suite covers that refresh path.
- `python-tests.log`, `postgresql-tests.log`, `deployment-tests.log`: retained final suite results. Frontend (10 tests plus TypeScript) and scanner (3 real-jq tests) passed earlier in this task, but their exact historical invocations/logs were not retained; no synthetic logs are supplied.
- `ubuntu-exclusion-audit.json`, `tar-metadata-audit.json`: bounded input/cohort investigations.

Use the normal release image and an empty disposable PostgreSQL 16 container with no external network. Run the ordinary image entrypoint, without intelligence mounts or a manual initial import. Supply your own test-only database and bootstrap credentials; none are included here. Record image identity, health, timestamps and peak process/container memory. Copy `scripts/verify-embedded-intelligence.py` into `/tmp/verify-embedded-intelligence.py` only after automatic import, set `PYTHONPATH=/app`, then run:

```text
python /tmp/verify-embedded-intelligence.py --already-installed --report /tmp/expanded-acceptance.json
```

For baseline coverage, copy the same verifier and `verify-baseline-coverage.py` into the prior release's isolated container, then pass the expanded report's `coverage.freshness_as_of` timestamp. This helper only reads database contents. Full counts are deliberately expensive offline acceptance work, not portal request-path queries.

For final runtime validation, start the final normal image against the already imported persistent database, preserving the isolated network. Copy the verifier and `verify-final-runtime.py`, then run:

```text
python /tmp/verify-final-runtime.py --verifier-path /tmp/verify-embedded-intelligence.py --report /tmp/final-smoke.json
```

The runtime smoke permits the unchanged-installer status update and otherwise checks read-only behavior. It locally sets the candidate limit to zero to exercise conservative overflow and restores it immediately; no production configuration is changed. Python socket guards complement Docker network isolation; they do not independently intercept native PostgreSQL client calls. Real publisher evidence is distinguished from a declared synthetic containing-image digest used only as a negative identity control.

Broad Python reproduction uses the normal portal environment, `PYTHONPATH=portal`, and the embedded-intelligence, CSAF, membership, projection, packaged-risk, source/record API, worker identity, Risk Profile/routes/SQL, VEX repository, verifier and classification test files listed in `test-files.txt`. PostgreSQL tests require a disposable explicitly configured loopback database and run in isolated schemas. Suite counts overlap and should not be summed.

Do not include signing keys, database URLs with credentials, bootstrap credentials, or local acquisition caches in published evidence. Retain verified input archives outside the repository for deterministic rebuilding: official live URLs are mutable.
