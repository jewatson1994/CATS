param([string]$Python = '')

# Requires a running Docker engine and a Python environment with portal test dependencies.
$ErrorActionPreference = 'Stop'
$repository = Split-Path -Parent $PSScriptRoot
if (-not $Python) {
    $Python = Join-Path $repository '.venv\Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $Python)) { $Python = 'python' }
}
$pythonCommand = (Get-Command $Python -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
Get-Command docker -ErrorAction Stop | Out-Null
$identity = 'cats-sbom-pg-' + [guid]::NewGuid().ToString('N')
$previousEnvironment = @{}
$isolatedEnvironment = @('CATS_TEST_DATABASE_URL', 'PYTEST_ADDOPTS', 'INTELLIGENCE_DATABASE_URL', 'INTELLIGENCE_DB_PASSWORD')
foreach ($key in (@('POSTGRES_PASSWORD', 'CATS_TEST_POSTGRES_URL') + $isolatedEnvironment)) {
    $previousEnvironment[$key] = [Environment]::GetEnvironmentVariable($key, 'Process')
}
$creationAttempted = $false
$created = $false
$result = 1

function Invoke-TestDocker {
    & docker @args
    if ($LASTEXITCODE -ne 0) { throw "Docker command failed with exit code $LASTEXITCODE" }
}

try {
    $env:POSTGRES_PASSWORD = [guid]::NewGuid().ToString('N')
    $creationAttempted = $true
    Invoke-TestDocker run --detach --name $identity --label cats.purpose=sbom-postgres-tests `
        --publish '127.0.0.1::5432' --env POSTGRES_PASSWORD `
        --env POSTGRES_USER=cats_test --env POSTGRES_DB=cats_sbom_test postgres:16-alpine | Out-Null
    $created = $true
    $ready = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        & docker exec $identity pg_isready --host 127.0.0.1 --username cats_test --dbname cats_sbom_test *> $null
        if ($LASTEXITCODE -eq 0) { $ready = $true; break }
        Start-Sleep -Seconds 1
    }
    if (-not $ready) { throw 'Disposable PostgreSQL did not become ready within 60 seconds' }
    $endpoint = (Invoke-TestDocker port $identity 5432/tcp).Trim()
    if ($endpoint -notmatch '^127\.0\.0\.1:(\d+)$') { throw "Unexpected test database endpoint: $endpoint" }
    $port = $Matches[1]
    $env:CATS_TEST_POSTGRES_URL = "postgresql+psycopg://cats_test:$($env:POSTGRES_PASSWORD)@127.0.0.1:${port}/cats_sbom_test"
    # Keep this fixed suite independent of other database targets or collect-only options.
    foreach ($key in $isolatedEnvironment) {
        Remove-Item -LiteralPath "Env:$key" -ErrorAction SilentlyContinue
    }
    Invoke-TestDocker exec $identity psql --username cats_test --dbname cats_sbom_test `
        --tuples-only --command 'SELECT version();'
    Push-Location (Join-Path $repository 'portal')
    try {
        $temporaryTests = Join-Path ([IO.Path]::GetTempPath()) $identity
        & $pythonCommand -m pytest tests/test_risk_vex_postgres.py tests/test_native_vex_boundaries.py `
            tests/test_sbom_postgres.py -k postgres -q -ra -p no:cacheprovider --basetemp $temporaryTests
        $result = $LASTEXITCODE
    } finally {
        Pop-Location
    }
} finally {
    if ($creationAttempted) {
        # docker run can create a container/volume and then fail to start it.
        & docker container inspect $identity *> $null
        if ($LASTEXITCODE -eq 0) {
            & docker rm --force --volumes $identity | Out-Null
            if ($LASTEXITCODE -ne 0) { Write-Warning "Could not remove disposable database $identity"; $result = 1 }
        } elseif ($created) {
            Write-Warning "Could not confirm cleanup of disposable database $identity"
            $result = 1
        }
    }
    foreach ($key in $previousEnvironment.Keys) {
        if ($null -eq $previousEnvironment[$key]) {
            Remove-Item -LiteralPath "Env:$key" -ErrorAction SilentlyContinue
        } else {
            [Environment]::SetEnvironmentVariable($key, $previousEnvironment[$key], 'Process')
        }
    }
}
exit $result
