param([string]$Image = 'cats-discovery:incremental')
$ErrorActionPreference = 'Stop'
$repository = Split-Path -Parent $PSScriptRoot
$identity = 'cats-discovery-e2e-' + [guid]::NewGuid().ToString('N').Substring(0,10)
$database = "$identity-db"
$worker = "$identity-worker"
$volume = "$identity-uploads"
$key = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes('0123456789abcdef0123456789abcdef'))
$environment = @('-e', "DATABASE_URL=postgresql+psycopg://acceptance:acceptance@$database/acceptance", '-e', "CATS_CONFIG_ENCRYPTION_KEY=$key", '-e', 'CATS_DISCOVERY_UPLOAD_ROOT=/data/discovery-uploads', '-e', 'PYTHONPATH=/app', '-e', 'CATS_DISCOVERY_RENDER_CACHE=true')
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
    Invoke-Docker run --rm --network $identity @environment $Image python -c 'from app.database import Base, engine; from app import models, discovery_models, durable_jobs; Base.metadata.create_all(engine)'
    Invoke-Docker run -d --name $worker --network $identity --read-only --cap-drop ALL --security-opt no-new-privileges:true --security-opt "seccomp=$repository/deploy/discovery-seccomp.json" --cpus 1 --memory 1g --pids-limit 128 --tmpfs "/tmp:rw,nosuid,nodev,size=536870912,mode=1777" --mount "type=volume,src=$volume,dst=/data/discovery-uploads,readonly" @environment $Image
    Invoke-Docker run --rm --network $identity --mount "type=volume,src=$volume,dst=/data/discovery-uploads" --mount "type=bind,src=$PSScriptRoot,dst=/acceptance,readonly" @environment $Image python /acceptance/discovery-deployed-acceptance.py
} finally {
    & docker logs $worker
    & docker rm -f $worker $database
    & docker volume rm $volume
    & docker network rm $identity
}



