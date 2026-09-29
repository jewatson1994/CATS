# Helm acquisition resource policy

HTTP chart archives are copied in at most 1 MiB chunks to private temporary
files, using `CATS_PUBLIC_MAX_CHART_BYTES` (default 512 MiB) as the compressed
byte limit, including responses without Content-Length. Owned downloads close
after staging, on transfer errors, and on retained-source extraction errors.
Repository index metadata remains a bounded in-memory YAML document.

`CATS_PUBLIC_HELM_TEMP_RESERVE_BYTES` optionally preserves a free-space margin
on the temporary filesystem (default `0`; nonnegative integer bytes). HTTP
copying checks available space before each write. OCI acquisition checks for
the compressed archive allowance plus reserve before Helm starts, and checks
the reserve again when Helm returns. OCI files are checked against the archive
limit and copied with the same bounded helper before the isolated pull
directory is removed.

OCI continues to use Helm and its existing authentication/environment and
additive CA configuration. `CATS_PUBLIC_HELM_PULL_TIMEOUT` retains its 180-second
default. A timeout terminates/waits for the Helm process through subprocess.run
and removes the temporary destination. Pre/post free-space checks are not a
filesystem quota and cannot prevent Helm itself from exceeding free space
during a pull; deployment-level temporary-storage quotas remain necessary for
that guarantee. Other concurrent writers can also consume the checked space.
