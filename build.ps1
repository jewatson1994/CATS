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
    $python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
    $pythonArgs = @()
    if (-not (Test-Path -LiteralPath $python)) {
        if (Get-Command py -ErrorAction SilentlyContinue) {
            $python = "py"
            $pythonArgs = @("-3")
        }
        elseif (Get-Command python -ErrorAction SilentlyContinue) {
            $python = "python"
        }
        else {
            throw "Python 3 is required to export verified validator image archives. Install Python 3 and retry."
        }
    }


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
    Write-Host "Preparing verified validator image archives..." -ForegroundColor Yellow
    $releasePython = $python
    $nodeReference = & $releasePython @pythonArgs -c "import sys; sys.path.insert(0, 'portal'); from app.deployment_validation import ValidationConfig; print(ValidationConfig.kind_node_image)"
    if ($LASTEXITCODE -ne 0) { throw "Could not resolve the trusted Kind image." }
    docker image inspect $nodeReference *> $null
    if ($LASTEXITCODE -ne 0) {
        docker pull $nodeReference
        if ($LASTEXITCODE -ne 0) { throw "Could not acquire the pinned Kind image." }
    }
    $releaseDirectory = Join-Path $PSScriptRoot ('.release-cache/managed-validator/' + [guid]::NewGuid().ToString('N'))
    & $releasePython @pythonArgs (Join-Path $PSScriptRoot 'scripts/prepare-docker-validator-release.py') --cats-image $expectedImage --output $releaseDirectory --activate-env (Join-Path $PSScriptRoot '.env')
    if ($LASTEXITCODE -ne 0) { throw "Validator release preparation failed." }
    $env:CATS_MANAGED_VALIDATOR_RELEASE_SOURCE = $releaseDirectory

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

    $portalContainer = docker @composeArgs ps -q portal

    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($portalContainer)) {
        throw "Could not locate the portal container."
    }

    $workerContainer = docker @composeArgs ps -q patch-worker

    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($workerContainer)) {
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

    foreach ($container in @($portalContainer, $workerContainer)) {
        $deployedImageId = docker inspect $container --format "{{.Image}}"
        if ($LASTEXITCODE -ne 0) {
            throw "Could not inspect the deployed image for container '$container'."
        }
        if ($deployedImageId -ne $expectedImageId) {
            throw "Container '$container' is using an older or different image. Expected '$expectedImageId' but found '$deployedImageId'."
        }
    }

    $releaseCheck = "import os; from app.managed_validator_release import load_release; r=load_release(); assert r['cats_image']['image_id'] == os.environ['EXPECTED_CATS_IMAGE_ID'], 'Validator release image mismatch'; print('HQ validator release verified.')"
    docker exec -e "EXPECTED_CATS_IMAGE_ID=$expectedImageId" $portalContainer /opt/cats-venv/bin/python -c $releaseCheck
    if ($LASTEXITCODE -ne 0) { throw "HQ validator release readiness verification failed." }

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
    Write-Host "Portal         : $portalImage" -ForegroundColor Green
    Write-Host "Patch Worker   : $workerImage" -ForegroundColor Green
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
