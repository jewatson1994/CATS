# Contributing to CATS

Use the [README](README.md) for deployment and the [documentation index](docs/README.md) for operator and architecture guides. Run the following commands from the repository root unless a command changes directories.

## Repository layout

| Path | Purpose |
| --- | --- |
| `portal/app/` and `portal/tests/` | Python application, durable workers, and backend tests |
| `portal/frontend/` | React interface, frontend tests, and pinned dependency lockfile |
| `cats-scanner/`, `scanning-main/`, `cats-image/` | Scanner tools, CLI, image builds, and standalone usage |
| `templates/` and `deploy/` | Deployment definitions, environment examples, worker isolation, and operational helpers |
| `scripts/` | Release/setup tooling, benchmarks, and verification utilities |
| `tests/` | OCI and lifecycle integration fixtures |
| `docs/` | Current guides, dated qualification evidence, and archived implementation records |

## Backend environment

The standalone portal Dockerfile pins Python 3.12; use that version for direct backend development. Create a virtual environment and install the pinned requirements.

On PowerShell:

```powershell
python -m venv .venv
.venv/Scripts/python -m pip install -r portal/requirements-dev.txt
$env:PYTHONPATH = "$PWD;$PWD/portal"
.venv/Scripts/python -m pytest portal/tests -q
```

On Linux:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r portal/requirements-dev.txt
PYTHONPATH=.:portal .venv/bin/python -m pytest portal/tests -q
```

Start with the tests covering the changed behavior by replacing `portal/tests` with specific test files. The backend fixture defaults to an in-memory SQLite database and stubs the large packaged-intelligence startup import for unrelated tests. PostgreSQL-specific checks require a **disposable** test database; `CATS_TEST_DATABASE_URL` may cause tests to drop and recreate its tables. Never point it at an application database. Docker, registry, scanner, Helm, and runtime qualification checks need their documented tools and fixtures; a unit-test pass does not qualify those deployments.

Scanner/CLI changes also have Python coverage under `scanning-main/tests`:

```sh
python -m pytest scanning-main/tests -q
```

Use the virtual environment's Python and the same `PYTHONPATH` settings above. See [scanner instructions](scanning-main/README.md) for shell fixtures and [lifecycle integration](tests/lifecycle/README.md) for the isolated Docker fixture.

## Frontend environment

The Dockerfiles pin Node **24.19.0** and pnpm **11.19.0**; the package manifest pins the package manager and frontend dependencies. With those tools available:

```sh
cd portal/frontend
pnpm install --frozen-lockfile
pnpm typecheck
pnpm lint --max-warnings 0
pnpm test
pnpm build
```

The build writes ignored assets to `portal/app/static/frontend`. Build them before starting the Python portal directly; container builds already do so. See [frontend architecture and acceptance](docs/react-frontend.md). Direct development also requires whichever background workers handle the queued operations being exercised.

## Deployment and release checks

Use [guided setup](docs/guided-setup.md) and the [template instructions](templates/README.md). For the local stack, Compose commands run from the repository root and explicitly name the relocated file:

```sh
docker compose --project-directory . --env-file .env -f templates/compose.local.yaml config --quiet
```

Use a configured local `.env`, copied from `templates/local.env.example` only for a new installation. For HTTPS main or replica deployments, use their matching templates and environment files instead. Keep deployment examples, setup packaging, and deployment tests consistent when changing paths or settings.

The release builder is `scripts/build-cats-release.py`; [image CI](.github/workflows/build-cats-tool.yml) builds and smoke-tests the full image before publication. Run relevant tests and validation for the change, and report checks that could not run with their prerequisites. Do not present old qualification reports or synthetic fixtures as current live acceptance.

## Branches, reviews, and repository hygiene

- Start a focused branch from current `main`; use a descriptive name such as `codex/fix-scan-export` for Codex-assisted work. Keep unrelated changes separate.
- Describe the problem, resulting behavior, and validation in the pull request. Include migration, compatibility, or operational consequences when they apply.
- Update the matching guide and environment example when changing user-facing behavior or configuration. Prefer links from the documentation index over adding more root-level handoffs.
- Keep credentials, real environment files, private keys, database backups, registry authentication, generated scan output, image exports, build caches, and frontend dependencies out of Git. Review new files against `.gitignore` before staging.
- Retain useful dated acceptance evidence with its scope and limitations. Put superseded implementation handoffs in `docs/archive/`; remove disposable scratch output instead of turning it into permanent documentation.
- Keep shared Codex context-engine memory, telemetry, planner, task, and graph artifacts outside this repository. Repository-local integration state is local configuration and is ignored by Git.
- Preserve the synchronized license copies in `LICENSE`, `portal/LICENSE`, and `cats-scanner/LICENSE`. Third-party code and data retain their separate notices.
