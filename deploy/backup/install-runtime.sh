#!/bin/sh
set -eu
# Executed only during connected image builds, never during deployment.
apk add --no-cache postgresql16 postgresql16-client su-exec
for tool in initdb pg_ctl postgres pg_dump pg_restore psql; do
    command -v "$tool"
done
pg_dump --version | grep 'PostgreSQL) 16\.'
postgres --version | grep 'PostgreSQL) 16\.'
id postgres
