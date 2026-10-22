param([string]$Image = 'cats:local', [string]$Archive = '', [string]$HelmSources = '[]', [string]$HelmOrigins = '[]', [string]$HelmTokenOrigins = '[]', [string]$ArtifactMirror = '', [string]$DiscoveryOptions = '{}', [switch]$AllowHelmNetwork)
$ErrorActionPreference = 'Stop'
$repository = Split-Path -Parent $PSScriptRoot
$identity = 'cats-discovery-e2e-' + [guid]::NewGuid().ToString('N').Substring(0,10)
$database = "$identity-db"
$worker = "$identity-worker"
$volume = "$identity-uploads"
$key = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes('0123456789abcdef0123456789abcdef'))
$environment = @('-e', "DATABASE_URL=postgresql+psycopg://acceptance:acceptance@$database/acceptance", '-e', "CATS_CONFIG_ENCRYPTION_KEY=$key", '-e', 'CATS_DISCOVERY_UPLOAD_ROOT=/data/discovery-uploads', '-e', 'PYTHONPATH=/app', '-e', 'CATS_DISCOVERY_RENDER_CACHE=true')
$environment += @('-e', "HELM_ALLOW_NETWORK=$($AllowHelmNetwork.IsPresent.ToString().ToLowerInvariant())", '-e', "CATS_DISCOVERY_HELM_SOURCES=$HelmSources", '-e', "CATS_DISCOVERY_HELM_ORIGINS=$HelmOrigins", '-e', "CATS_DISCOVERY_HELM_TOKEN_ORIGINS=$HelmTokenOrigins")
$environment += @('-e', "DISCOVERY_ACCEPTANCE_OPTIONS=$DiscoveryOptions")
$archiveMount = @()
$mirrorMount = @()
if ($ArtifactMirror) {
    $mirrorPath = (Resolve-Path -LiteralPath $ArtifactMirror).Path
    $mirrorMount = @('--mount', "type=bind,src=$mirrorPath,dst=/acceptance-mirror,readonly")
    $environment += @('-e', 'CATS_DISCOVERY_ARTIFACT_MANIFEST=/acceptance-mirror/manifest.json')
}
if ($Archive) {
    $archivePath = (Resolve-Path -LiteralPath $Archive).Path
    $archiveMount = @('--mount', "type=bind,src=$archivePath,dst=/acceptance-source.zip,readonly")
    $environment += @('-e', 'DISCOVERY_ACCEPTANCE_ARCHIVE=/acceptance-source.zip')
}
function Invoke-Docker {
    & docker @args
    if ($LASTEXITCODE -ne 0) { throw "Docker command failed with exit code $LASTEXITCODE" }
}
try {
    Invoke-Docker network create $identity
    Invoke-Docker volume create $volume
    Invoke-Docker run -d --name $database --network $identity -e POSTGRES_USER=acceptance -e POSTGRES_PASSWORD=acceptance -e POSTGRES_DB=acceptance postgres:16-alpine
    $ready = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        & docker exec $database pg_isready -U acceptance -d acceptance *> $null
        if ($LASTEXITCODE -eq 0) { $ready = $true; break }
        Start-Sleep -Seconds 1
    }
    if (-not $ready) { throw 'Disposable PostgreSQL did not become ready' }
    Invoke-Docker run --rm --network $identity @environment --entrypoint /opt/cats-venv/bin/python $Image -c 'from app.database import Base, engine; from app import models, discovery_models, durable_jobs; Base.metadata.create_all(engine)'
    Invoke-Docker run -d --name $worker --network $identity --read-only --cap-drop ALL --security-opt no-new-privileges:true --security-opt "seccomp=$repository/deploy/discovery-seccomp.json" --cpus 1 --memory 1g --pids-limit 128 --tmpfs "/tmp:rw,nosuid,nodev,size=536870912,mode=1777" --mount "type=volume,src=$volume,dst=/data/discovery-uploads,readonly" @mirrorMount @environment --user 10003:10003 --entrypoint /opt/cats-venv/bin/python $Image -m app.discovery_worker
    Invoke-Docker run --rm --network $identity --mount "type=volume,src=$volume,dst=/data/discovery-uploads" --mount "type=bind,src=$PSScriptRoot,dst=/acceptance,readonly" @archiveMount @environment --entrypoint /opt/cats-venv/bin/python $Image /acceptance/discovery-deployed-acceptance.py
} finally {
    & docker logs $worker
    & docker rm -f $worker $database
    & docker volume rm $volume
    & docker network rm $identity
}
