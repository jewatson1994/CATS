[CmdletBinding()]
param(
    [string]$EnvFile = ".env",
    [string]$ComposeFile = "compose.yaml",
    [string]$ResultsRoot = ".demo-scan-results",
    [string]$PortalUrl = "http://portal:8000",
    [string]$NetworkName = "cats_default",
    [switch]$Plan
)

$ErrorActionPreference = "Stop"
if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue) {
    $PSNativeCommandUseErrorActionPreference = $false
}
$repositoryRoot = Split-Path -Parent $PSScriptRoot

function Resolve-RepositoryPath {
    param([Parameter(Mandatory)][string]$Path)
    if ([IO.Path]::IsPathRooted($Path)) {
        return [IO.Path]::GetFullPath($Path)
    }
    return [IO.Path]::GetFullPath((Join-Path $repositoryRoot $Path))
}

function Read-DotEnv {
    param([Parameter(Mandatory)][string]$Path)
    $values = @{}
    foreach ($line in Get-Content -LiteralPath $Path) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith("#") -or -not $trimmed.Contains("=")) {
            continue
        }
        $parts = $trimmed.Split("=", 2)
        $name = $parts[0].Trim()
        $value = $parts[1].Trim()
        if ($value.Length -ge 2) {
            $isDoubleQuoted = $value.StartsWith('"') -and $value.EndsWith('"')
            $isSingleQuoted = $value.StartsWith("'") -and $value.EndsWith("'")
            if ($isDoubleQuoted -or $isSingleQuoted) {
                $value = $value.Substring(1, $value.Length - 2)
            }
        }
        $values[$name] = $value
    }
    return $values
}

function Invoke-Docker {
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [switch]$Capture
    )
    if ($Capture) {
        $output = & docker @Arguments 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Docker command failed: $($output -join [Environment]::NewLine)"
        }
        return $output
    }
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        # Windows PowerShell wraps native stderr as NativeCommandError records.
        # Let Docker report its own exit code so one failed image does not abort
        # processing of the remaining services.
        $ErrorActionPreference = "Continue"
        & docker @Arguments 2>&1 | ForEach-Object { Write-Host $_ }
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    return $exitCode
}

$services = @(
    [pscustomobject]@{ Id = "real-alpine"; Name = "Real Image - Alpine"; Version = "3.19.1"; Image = "docker.io/library/alpine:3.19.1"; Description = "Alpine Linux container image" },
    [pscustomobject]@{ Id = "real-busybox"; Name = "Real Image - BusyBox"; Version = "1.36.1"; Image = "docker.io/library/busybox:1.36.1"; Description = "BusyBox container image" },
    [pscustomobject]@{ Id = "real-debian"; Name = "Real Image - Debian"; Version = "12.5"; Image = "docker.io/library/debian:12.5-slim"; Description = "Debian slim container image" },
    [pscustomobject]@{ Id = "real-ubuntu"; Name = "Real Image - Ubuntu"; Version = "22.04"; Image = "docker.io/library/ubuntu:22.04"; Description = "Ubuntu LTS container image" },
    [pscustomobject]@{ Id = "real-nginx"; Name = "Real Image - NGINX"; Version = "1.25.4"; Image = "docker.io/library/nginx:1.25.4-alpine"; Description = "NGINX Alpine container image" },
    [pscustomobject]@{ Id = "real-httpd"; Name = "Real Image - Apache HTTP Server"; Version = "2.4.58"; Image = "docker.io/library/httpd:2.4.58-alpine"; Description = "Apache HTTP Server Alpine container image" },
    [pscustomobject]@{ Id = "real-redis"; Name = "Real Image - Redis"; Version = "7.2.4"; Image = "docker.io/library/redis:7.2.4-alpine"; Description = "Redis Alpine container image" },
    [pscustomobject]@{ Id = "real-postgres"; Name = "Real Image - PostgreSQL"; Version = "16.2"; Image = "docker.io/library/postgres:16.2-alpine"; Description = "PostgreSQL Alpine container image" },
    [pscustomobject]@{ Id = "real-python"; Name = "Real Image - Python"; Version = "3.11.8"; Image = "docker.io/library/python:3.11.8-slim-bookworm"; Description = "Python slim Bookworm container image" },
    [pscustomobject]@{ Id = "real-node"; Name = "Real Image - Node.js"; Version = "20.11.1"; Image = "docker.io/library/node:20.11.1-bookworm-slim"; Description = "Node.js slim Bookworm container image" }
)

if ($Plan) {
    $services | Select-Object Id, Name, Version, Image | Format-Table -AutoSize
    return
}

$envPath = Resolve-RepositoryPath $EnvFile
$composePath = Resolve-RepositoryPath $ComposeFile
$resultsPath = Resolve-RepositoryPath $ResultsRoot
if (-not (Test-Path -LiteralPath $envPath -PathType Leaf)) { throw "Environment file not found: $envPath" }
if (-not (Test-Path -LiteralPath $composePath -PathType Leaf)) { throw "Compose file not found: $composePath" }
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker was not found. Run this script in the terminal where Docker Desktop is available."
}

$dotenv = Read-DotEnv $envPath
$pipelineToken = if ($env:PIPELINE_API_TOKEN) { $env:PIPELINE_API_TOKEN } else { $dotenv["PIPELINE_API_TOKEN"] }
$catsImage = if ($env:CATS_IMAGE) { $env:CATS_IMAGE } elseif ($dotenv["CATS_IMAGE"]) { $dotenv["CATS_IMAGE"] } else { "cats:1.3" }
if (-not $pipelineToken) { throw "PIPELINE_API_TOKEN is missing from $envPath" }

$runningServices = @(Invoke-Docker -Capture -Arguments @(
    "compose", "--env-file", $envPath, "-f", $composePath,
    "ps", "--services", "--status", "running"
))
if ($runningServices -notcontains "portal" -or $runningServices -notcontains "db") {
    throw "The canonical portal stack is not running. Start it with: docker compose --env-file `"$envPath`" -f `"$composePath`" up -d --wait"
}
Invoke-Docker -Capture -Arguments @("network", "inspect", $NetworkName) | Out-Null
Invoke-Docker -Capture -Arguments @("image", "inspect", $catsImage) | Out-Null

$runId = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$runPath = Join-Path $resultsPath $runId
New-Item -ItemType Directory -Path $runPath -Force | Out-Null
$tokenPath = Join-Path $runPath ".portal-token"
[IO.File]::WriteAllText($tokenPath, $pipelineToken, [Text.UTF8Encoding]::new($false))

$summary = [Collections.Generic.List[object]]::new()
try {
    for ($index = 0; $index -lt $services.Count; $index++) {
        $service = $services[$index]
        $number = $index + 1
        $jobPath = Join-Path $runPath $service.Id
        $inputPath = Join-Path $jobPath "input"
        New-Item -ItemType Directory -Path $inputPath -Force | Out-Null

        $serviceYaml = @"
service:
  id: $($service.Id)
  name: "$($service.Name)"
  version: "$($service.Version)"
  owner: "CATS Local Demo"
  poc: "Not provided"
  groups:
    - "Real Image Scans"
overview:
  description: "$($service.Description), scanned locally by CATS from its real public image."
"@
        $imagesYaml = @"
images:
  - "$($service.Image)"
"@
        [IO.File]::WriteAllText((Join-Path $inputPath "service.yml"), $serviceYaml, [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText((Join-Path $inputPath "images.yml"), $imagesYaml, [Text.UTF8Encoding]::new($false))

        # Keep the Bash syntax out of PowerShell's native argument marshaller.
        # Passing only the script path to `bash` works in Windows PowerShell 5.1
        # and PowerShell 7 without command-substitution quoting problems.
        $runnerPath = Join-Path $jobPath "run-ingest.sh"
        $runnerScript = @'
#!/usr/bin/env bash
set -euo pipefail
export CATS_PORTAL_TOKEN="$(cat /run/secrets/cats_portal_token)"
cats prepare --source /job/input --output /job/prepared
cats evaluate --source /job/prepared --output /job/results
cats push assessment --input /job/results/portal-result.json
'@
        [IO.File]::WriteAllText($runnerPath, $runnerScript, [Text.UTF8Encoding]::new($false))

        Write-Host ""
        Write-Host "[$number/$($services.Count)] Scanning and ingesting $($service.Name) ($($service.Image))" -ForegroundColor Cyan
        $containerName = "cats-real-scan-$($service.Id)-$PID"
        $exitCode = Invoke-Docker -Arguments @(
            "run", "--rm", "--name", $containerName,
            "--network", $NetworkName,
            "--volume", "/var/run/docker.sock:/var/run/docker.sock",
            "--mount", "type=bind,source=$jobPath,target=/job",
            "--mount", "type=bind,source=$tokenPath,target=/run/secrets/cats_portal_token,readonly",
            "--env", "CATS_PORTAL_URL=$PortalUrl",
            "--env", "CATS_OFFLINE=true",
            "--env", "TRIVY_IMAGE_CONFIG_SCAN_ENABLED=true",
            "--env", "DOCKLE_IMAGE_CONFIG_SCAN_ENABLED=true",
            "--env", "REPORT_RAW_FINDINGS=false",
            "--env", "CI_PROJECT_ID=cats-real-images-$($service.Id)",
            "--env", "CI_PIPELINE_ID=$runId-$number",
            "--env", "CI_PIPELINE_URL=local://cats-real-images/$runId/$($service.Id)",
            "--env", "CI_COMMIT_SHA=local-real-image-scan",
            $catsImage, "bash", "/job/run-ingest.sh"
        )

        $resultFile = Join-Path $jobPath "results\portal-result.json"
        if ($exitCode -eq 0 -and (Test-Path -LiteralPath $resultFile -PathType Leaf)) {
            $payload = Get-Content -LiteralPath $resultFile -Raw | ConvertFrom-Json
            $summary.Add([pscustomobject]@{
                Service = $service.Name; Image = $service.Image; Status = "Ingested"
                Findings = @($payload.findings).Count
                ConfigurationFindings = @($payload.policy_findings).Count
            })
        }
        else {
            $summary.Add([pscustomobject]@{
                Service = $service.Name; Image = $service.Image; Status = "Failed"
                Findings = "-"; ConfigurationFindings = "-"
            })
        }
    }
}
finally {
    if (Test-Path -LiteralPath $tokenPath) { Remove-Item -LiteralPath $tokenPath -Force }
}

Write-Host ""
$summary | Format-Table -AutoSize
Write-Host "Raw scan output: $runPath"
$failed = @($summary | Where-Object Status -eq "Failed")
if ($failed.Count -gt 0) {
    throw "$($failed.Count) image scan(s) failed; the remaining services were still processed."
}
