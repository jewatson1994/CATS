$ErrorActionPreference = "Stop"

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

Write-Host ""
Write-Host "Building and deploying CATS version $version" -ForegroundColor Green
Write-Host "Target image: $expectedImage" -ForegroundColor Cyan
Write-Host ""

try {

    # ---------------------------------------------------------
    # Stage 1 - Build scanner/base image
    # ---------------------------------------------------------

    Write-Host "[1/4] Building catscan-base:local..." -ForegroundColor Yellow

    docker build `
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
        --build-arg CATSCAN_BASE_IMAGE=catscan-base:local `
        --build-arg CATS_VERSION=$version `
        -f cats-image/Dockerfile.all-in-one `
        -t $expectedImage `
        .

    if ($LASTEXITCODE -ne 0) {
        throw "CATS image build failed."
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

    docker compose up `
        -d `
        --force-recreate `
        --wait `
        portal patch-worker

    if ($LASTEXITCODE -ne 0) {
        throw "Docker Compose recreation failed."
    }

    Write-Host ""
    Write-Host "Portal and patch-worker recreated successfully." -ForegroundColor Green
    Write-Host ""

    # ---------------------------------------------------------
    # Stage 4 - Verify deployed images
    # ---------------------------------------------------------

    Write-Host "[4/4] Verifying deployed CATS images..." -ForegroundColor Yellow
    Write-Host ""

    $portalContainer = docker compose ps -q portal

    if ([string]::IsNullOrWhiteSpace($portalContainer)) {
        throw "Could not locate the portal container."
    }

    $workerContainer = docker compose ps -q patch-worker

    if ([string]::IsNullOrWhiteSpace($workerContainer)) {
        throw "Could not locate the patch-worker container."
    }

    $portalImage = docker inspect $portalContainer --format "{{.Config.Image}}"

    if ($LASTEXITCODE -ne 0) {
        throw "Could not inspect the portal container."
    }

    $workerImage = docker inspect $workerContainer --format "{{.Config.Image}}"

    if ($LASTEXITCODE -ne 0) {
        throw "Could not inspect the patch-worker container."
    }

    Write-Host "Deployment Verification" -ForegroundColor Cyan
    Write-Host "----------------------------------------"
    Write-Host "Expected:     $expectedImage"
    Write-Host "Portal:       $portalImage"
    Write-Host "Patch Worker: $workerImage"
    Write-Host "----------------------------------------"
    Write-Host ""

    if ($portalImage -ne $expectedImage) {
        throw "Portal image mismatch. Expected '$expectedImage' but found '$portalImage'."
    }

    if ($workerImage -ne $expectedImage) {
        throw "Patch-worker image mismatch. Expected '$expectedImage' but found '$workerImage'."
    }

    Write-Host "Image verification successful." -ForegroundColor Green
    Write-Host ""

    # ---------------------------------------------------------
    # Final status
    # ---------------------------------------------------------

    Write-Host "========================================" -ForegroundColor Green
    Write-Host " CATS $version REBUILD COMPLETE" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Expected Image : $expectedImage" -ForegroundColor Cyan
    Write-Host "Portal         : $portalImage" -ForegroundColor Green
    Write-Host "Patch Worker   : $workerImage" -ForegroundColor Green
    Write-Host ""

    docker compose ps
}
catch {

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
