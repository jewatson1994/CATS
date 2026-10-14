$ErrorActionPreference = "Stop"
$env:COMPOSE_ENV_FILES = Join-Path $PSScriptRoot '.env'

Set-Location -LiteralPath $PSScriptRoot
$composeArgs = @('compose', '--project-directory', $PSScriptRoot, '-f', (Join-Path $PSScriptRoot 'compose.yaml'), '-p', 'cats')

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "          CATS Rebuild Utility" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ---------------------------------------------------------
# Ask for version
# ---------------------------------------------------------

$version = Read-Host "Enter CATS version (example: 1.3)"

if ([string]::IsNullOrWhiteSpace($version)) {
    Write-Host "ERROR: Version cannot be empty." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

$version = $version.Trim()
if ($version.StartsWith("v", [System.StringComparison]::OrdinalIgnoreCase)) {
    $version = $version.Substring(1)
}
if ($version -notmatch '^[0-9]+(?:\.[0-9]+){1,3}(?:[-+][0-9A-Za-z.-]+)?$') {
    Write-Host "ERROR: Enter a version such as 1.3." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

$expectedImage = "cats:$version"
$buildExitCode = 0

Write-Host ""
Write-Host "Building and deploying CATS version $version" -ForegroundColor Green
Write-Host "Target image: $expectedImage" -ForegroundColor Cyan
Write-Host ""

try {
    # Resolve the registry bind exactly as Compose does; never let Docker create it
    # silently as a root-owned directory. Empty directories support anonymous pulls.
    $registryAuthSource = $env:CATS_SCAN_REGISTRY_AUTH_SOURCE
    if ([string]::IsNullOrWhiteSpace($registryAuthSource)) {
        $envFile = Join-Path $PSScriptRoot '.env'
        if (Test-Path -LiteralPath $envFile) {
            $registrySetting = Get-Content -LiteralPath $envFile | Where-Object { $_ -match '^\s*CATS_SCAN_REGISTRY_AUTH_SOURCE\s*=' } | Select-Object -Last 1
            if ($registrySetting) {
                $registryAuthSource = ($registrySetting -split '=', 2)[1].Trim().Trim('"').Trim("'")
            }
        }
    }
    if ([string]::IsNullOrWhiteSpace($registryAuthSource)) { $registryAuthSource = './scan-registry-auth' }
    if (-not [System.IO.Path]::IsPathRooted($registryAuthSource)) {
        $registryAuthSource = Join-Path $PSScriptRoot $registryAuthSource
    }
    $registryAuthSource = [System.IO.Path]::GetFullPath($registryAuthSource)
    if (-not (Test-Path -LiteralPath $registryAuthSource)) {
        New-Item -ItemType Directory -Path $registryAuthSource -Force | Out-Null
    }
    $registryDirectory = Get-Item -LiteralPath $registryAuthSource
    if (-not $registryDirectory.PSIsContainer -or ($registryDirectory.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw 'Registry authentication source must be a real directory, not a file or symbolic link.'
    }
    $registryConfig = Join-Path $registryAuthSource 'config.json'
    if (Test-Path -LiteralPath $registryConfig) {
        $registryConfigItem = Get-Item -LiteralPath $registryConfig
        if ($registryConfigItem.PSIsContainer -or ($registryConfigItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            throw 'Registry config.json must be a regular file.'
        }
        try {
            $registryConfigText = Get-Content -LiteralPath $registryConfig -Raw
            if (-not $registryConfigText.TrimStart().StartsWith('{')) { throw 'Expected object' }
            $null = $registryConfigText | ConvertFrom-Json -ErrorAction Stop
        }
        catch { throw 'Registry config.json must contain a valid JSON object.' }
    }
    $env:CATS_SCAN_REGISTRY_AUTH_SOURCE = $registryAuthSource
    # ---------------------------------------------------------
    # Stage 1 - Build scanner/base image
    # ---------------------------------------------------------

    Write-Host "[1/4] Building catscan-base:local..." -ForegroundColor Yellow

    docker build `
        --platform linux/amd64 `
        -f cats-scanner/Dockerfile `
        -t catscan-base:local `
        cats-scanner

    if ($LASTEXITCODE -ne 0) {
        throw "Scanner/base image build failed."
    }

    Write-Host ""
    Write-Host "Scanner/base image built successfully." -ForegroundColor Green
    Write-Host ""

    # ---------------------------------------------------------
    # Stage 2 - Build CATS image
    # ---------------------------------------------------------

    Write-Host "[2/4] Building $expectedImage..." -ForegroundColor Yellow

    docker build `
        --platform linux/amd64 `
        --build-arg CATSCAN_BASE_IMAGE=catscan-base:local `
        --build-arg CATS_VERSION=$version `
        -f cats-image/Dockerfile.all-in-one `
        -t $expectedImage `
        .

    if ($LASTEXITCODE -ne 0) {
        throw "CATS image build failed."
    }

    $expectedImageId = docker image inspect $expectedImage --format "{{.Id}}"
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($expectedImageId)) {
        throw "Could not identify the newly built CATS image."
    }

    Write-Host ""
    Write-Host "$expectedImage built successfully." -ForegroundColor Green
    Write-Host ""

    # ---------------------------------------------------------
    # Stage 3 - Deploy the EXACT image we just built
    # ---------------------------------------------------------

    Write-Host "[3/4] Deploying $expectedImage..." -ForegroundColor Yellow

    # Explicitly select the versioned image built above. Compose's fallback is
    # cats:local for development and never points at an older release.
    $env:CATS_IMAGE = $expectedImage

    Write-Host "CATS_IMAGE=$env:CATS_IMAGE" -ForegroundColor Cyan
    Write-Host ""

    docker @composeArgs up `
        -d `
        --force-recreate `
        --wait `
        portal portal-control patch-worker scan-worker remediation-worker export-worker provisioning-worker

    if ($LASTEXITCODE -ne 0) {
        throw "Docker Compose recreation failed."
    }

    Write-Host ""
    Write-Host "Portal and all six worker/control services recreated successfully." -ForegroundColor Green
    Write-Host ""

    # ---------------------------------------------------------
    # Stage 4 - Verify deployed images
    # ---------------------------------------------------------

    Write-Host "[4/4] Verifying deployed CATS images..." -ForegroundColor Yellow
    Write-Host ""

    $services = @('portal', 'portal-control', 'patch-worker', 'scan-worker', 'remediation-worker', 'export-worker', 'provisioning-worker')
    foreach ($service in $services) {
        $container = docker @composeArgs ps -q $service
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($container)) {
            throw "Could not locate the $service container."
        }
        $deployedImage = docker inspect $container --format "{{.Config.Image}}"
        if ($LASTEXITCODE -ne 0 -or $deployedImage -ne $expectedImage) {
            throw "$service image mismatch or inspection failed. Expected '$expectedImage'."
        }
        $deployedImageId = docker inspect $container --format "{{.Image}}"
        if ($LASTEXITCODE -ne 0 -or $deployedImageId -ne $expectedImageId) {
            throw "$service is using an older or different image. Expected '$expectedImageId'."
        }
        Write-Host "$service : $deployedImage ($deployedImageId)" -ForegroundColor Green
    }

    Write-Host "Image verification successful." -ForegroundColor Green
    Write-Host ""

    # ---------------------------------------------------------
    # Final status
    # ---------------------------------------------------------

    docker @composeArgs ps
    if ($LASTEXITCODE -ne 0) {
        throw "Could not read the final deployment status."
    }

    Write-Host "========================================" -ForegroundColor Green
    Write-Host " CATS $version REBUILD COMPLETE" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Expected Image : $expectedImage" -ForegroundColor Cyan
    Write-Host ""

}
catch {
    $buildExitCode = 1

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host " BUILD / DEPLOYMENT FAILED" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host ""
    Write-Host $_ -ForegroundColor Red
    Write-Host ""
}

Write-Host ""
Read-Host "Press Enter to close"
exit $buildExitCode
