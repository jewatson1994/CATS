#!/bin/sh
set -eu

# Fail before interpolation if a value is not a plain DNS hostname.
for hostname in "${CATS_PORTAL_HOSTNAME:?Set CATS_PORTAL_HOSTNAME}" "${CATS_OCI_HOSTNAME:?Set CATS_OCI_HOSTNAME}"; do
    case "$hostname" in
        *[!A-Za-z0-9.-]*)
            echo "CATS routing requires plain DNS hostnames without schemes, paths or ports." >&2
            exit 1
            ;;
    esac
    if ! printf '%s\n' "$hostname" | grep -Eq '^([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$'; then
        echo "CATS routing requires plain DNS hostnames without schemes, paths or ports." >&2
        exit 1
    fi
done

if [ "$(printf '%s' "$CATS_PORTAL_HOSTNAME" | tr '[:upper:]' '[:lower:]')" = "$(printf '%s' "$CATS_OCI_HOSTNAME" | tr '[:upper:]' '[:lower:]')" ]; then
    echo "The portal and OCI proxy must use different hostnames." >&2
    exit 1
fi

# Substitute only deployment settings; retain Nginx's own $variables.
envsubst '${CATS_PORTAL_HOSTNAME} ${CATS_OCI_HOSTNAME}' \
    < /etc/nginx/cats.conf.template > /tmp/nginx.conf
nginx -t -q -c /tmp/nginx.conf
exec nginx -c /tmp/nginx.conf -g 'daemon off;'
