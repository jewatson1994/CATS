"""Shared, fail-closed offline tool execution for all worker actions.

Acquisition, database access and publication stay in the caller. Native tools
see only explicitly staged inputs, private scratch space and an empty network.
"""
from __future__ import annotations

import json
import os
import platform
import re
import struct
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time
import tempfile
import contextlib
import secrets
import shutil
from pathlib import PurePosixPath

from .action_supervisor import supervised_command
from .scanner_errors import ScannerDiagnostic, scanner_failure_message, scanner_failure_reason


class RendererError(RuntimeError):
    def __init__(self, message, *, value_paths=(), infrastructure=False, reason=None, scanner_diagnostic=None):
        super().__init__(message)
        self.value_paths = list(value_paths)
        self.infrastructure = infrastructure
        self.reason = reason
        self.scanner_diagnostic = scanner_diagnostic


def renderer_failure_reason(stderr):
    """Classify known native failures without retaining stderr or supplied values."""
    text = stderr.lower()
    if ('must specify --enable-helm' in text or 'is helm installed?' in text
            or ('helm' in text and 'executable file not found' in text)):
        return 'helm_unavailable'
    if any(marker in text for marker in ('helm pull', 'failed to fetch', 'failed to download',
                                         'looks like', 'no cached repo found', 'chart repository')):
        return 'artifact_retrieval_failed'
    if any(marker in text for marker in ('values don\'t meet the specifications', 'values do not meet the specifications',
                                         'cannot unmarshal', 'error converting yaml to json', 'yaml: line')):
        return 'invalid_values_or_yaml'
    if any(marker in text for marker in ('no such file or directory', 'must resolve to a file',
                                         'unable to find one of', 'missing in charts/ directory')):
        return 'missing_resource'
    if missing_value_paths(stderr) or 'nil pointer evaluating' in text:
        return 'required_values'
    if any(marker in text for marker in ('execution error at', 'template:', 'error calling', 'parse error at')):
        return 'template_error'
    if any(marker in text for marker in ('failed to find unique target for patch', 'no matches for id', 'unable to find target')):
        return 'patch_target_missing'
    return 'render_failed'


def missing_value_paths(stderr):
    # Retain identifiers only, never arbitrary template messages or supplied values.
    identifier = r"[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_][A-Za-z0-9_-]*)*"
    paths = re.findall(r"\.Values\.(" + identifier + r")", stderr)
    # Chart validation often names keys in backticks rather than Go expressions.
    paths += re.findall(r"`(" + identifier + r")`", stderr)
    # Helm required() messages also use unquoted dotted configuration keys.
    paths += re.findall(r"(?i)please set (" + identifier + r")", stderr)
    return sorted({path for path in paths if len(path) <= 160})[:50]


TOOLS = {
    "helm": ("/usr/local/bin/helm", []),
    "kustomize": ("/usr/local/bin/kubectl", ["kustomize"]),
    "compose": ("/usr/local/bin/docker-compose", []),
}
SCANNERS = {name: ("/usr/local/bin/" + name, []) for name in ("syft", "grype", "trivy", "dockle")}
PLATFORM = sys.platform


def _effective_uid() -> int:
    return os.geteuid()


def sandbox_command(tool: str, args: list[str], cwd: str | Path, *,
                    read_only=None, writable=None, environment=None, probe=False,
                    _identity_prepared=False) -> list[str]:
    if PLATFORM != "linux":
        raise RendererError("Offline actions require Linux isolation", infrastructure=True)
    if _effective_uid() == 0 and not _identity_prepared:
        raise RendererError("Offline actions require a non-root tool identity", infrastructure=True)
    available = {**TOOLS, **SCANNERS}
    if tool not in available:
        raise RendererError("Unsupported offline tool")
    required = {"helm": {"template", "lint"}, "compose": {"config"}}
    command_index = 0
    if tool == "compose":
        # Compose's global options precede the subcommand in Discovery.
        while command_index < len(args) and args[command_index] in {
            "--project-name", "-p", "--file", "-f", "--env-file", "--profile",
        }:
            if command_index + 1 >= len(args):
                raise RendererError("Incomplete Compose rendering option")
            command_index += 2
    if not probe and tool in required and (command_index >= len(args) or args[command_index] not in required[tool]):
        raise RendererError("Only offline rendering commands are permitted")
    forbidden = ("--enable-helm", "--enable-alpha-plugins", "--enable-exec",
                 "--post-renderer", "--post-renderer-args", "--dependency-update")
    if any(str(arg).split("=", 1)[0] in forbidden for arg in args):
        raise RendererError("Renderer extensions are disabled")
    executable, prefix = available[tool]
    if not Path("/usr/bin/bwrap").is_file() or not Path(executable).is_file():
        raise RendererError("Required isolated tool is unavailable", infrastructure=True)
    source = Path(cwd).resolve(strict=True)
    if not source.is_dir() or source == Path("/"):
        raise RendererError("Invalid action source directory")
    # Only static native renderer binaries and this job's source are visible.
    # No worker /proc, environment, application files, database or upload volume.
    # Keep the private PID namespace without mounting procfs: Docker's locked
    # /proc masks can prevent a nested user namespace from creating that mount.
    command = ["/usr/bin/bwrap", "--die-with-parent", "--new-session",
               "--unshare-all", "--unshare-user", "--cap-drop", "ALL",
               "--clearenv", "--ro-bind", executable, "/tool",
               "--ro-bind", str(source), "/source", "--tmpfs", "/tmp",
               "--tmpfs", "/cache", "--dir", "/inputs",
               "--dev", "/dev", "--chdir", "/source"]
    destinations = set()
    for flag, mounts in (("--ro-bind", read_only or {}), ("--bind", writable or {})):
        for host, destination in mounts.items():
            target = PurePosixPath(destination)
            if (not target.is_absolute() or '..' in target.parts or str(target) != str(destination)
                    or len(target.parts) < 3 or target.parts[1] not in {"inputs", "cache"}
                    or destination in destinations):
                raise RendererError("Invalid offline action mount")
            destinations.add(destination)
            command += [flag, str(Path(host).resolve(strict=True)), str(target)]
    for key, value in {
        "HOME": "/tmp", "PATH": "/nonexistent", "TMPDIR": "/tmp",
        "HELM_PLUGINS": "/nonexistent", "HELM_CACHE_HOME": "/tmp/helm/cache",
        "HELM_CONFIG_HOME": "/tmp/helm/config", "HELM_DATA_HOME": "/tmp/helm/data",
        "KUBECONFIG": "/nonexistent", "DOCKER_CONFIG": "/nonexistent",
        "COMPOSE_DISABLE_ENV_FILE": "1", "COMPOSE_ANSI": "never",
    }.items():
        command += ["--setenv", key, value]
    # Only scanner policy knobs may be supplied, never process/control secrets.
    permitted = {"GRYPE_DB_CACHE_DIR", "GRYPE_DB_AUTO_UPDATE", "GRYPE_DB_VALIDATE_AGE",
                 "GRYPE_DB_MAX_ALLOWED_BUILT_AGE", "GRYPE_CHECK_FOR_APP_UPDATE",
                 "GRYPE_DB_REQUIRE_UPDATE_CHECK", "GRYPE_DB_VALIDATE_BY_HASH_ON_START",
                 "SYFT_CHECK_FOR_APP_UPDATE", "TRIVY_CACHE_DIR", "TRIVY_OFFLINE_SCAN",
                 "TRIVY_SKIP_DB_UPDATE", "TRIVY_SKIP_JAVA_DB_UPDATE", "TRIVY_SKIP_CHECK_UPDATE",
                 "SYFT_FILE_METADATA_CATALOGER_ENABLED", "SYFT_FILE_METADATA_SELECTION",
                 "GRYPE_SEARCH_INDEXED_ARCHIVES", "GRYPE_SEARCH_UNINDEXED_ARCHIVES"}
    for key, value in (environment or {}).items():
        if key not in permitted:
            raise RendererError("Unsupported offline tool environment setting")
        command += ["--setenv", key, str(value)]
    if tool == "kustomize" and args and args[0] == "build":
        args = args[1:]
    translated = []
    for arg in args:
        value = str(arg)
        if value == str(source) or value.startswith(str(source) + os.sep):
            value = "/source" + value[len(str(source)):]
        translated.append(value)
    return command + ["--", "/tool", *prefix, *translated]


def isolated_runner(tool: str, args: list[str], cwd: str | Path, *,
                    timeout: float = 60, max_output: int | None = None, check_cancelled=None) -> dict[str, str]:
    return offline_runner(tool, args, cwd, timeout=timeout, max_output=max_output,
                          check_cancelled=check_cancelled)


@contextlib.contextmanager
def _staged_identity(cwd, read_only, writable):
    """Root brokers drop identity; no chown of user inputs or shared databases.

    Scanner workers already execute under a per-attempt identity. Root brokers
    (patch/delivery) use a fresh identity and a private copy, including private
    writable caches. Symlinks are never followed when copying/chowning inputs.
    """
    root = _effective_uid() == 0
    with tempfile.TemporaryDirectory(prefix="cats-action-") as directory:
        staging = Path(directory)
        uid = 200000 + secrets.randbelow(1000000000) if root else None
        def copy(source, label):
            source, target = Path(source), staging / label
            if source.is_symlink():
                raise RendererError("Action mount roots cannot be symlinks")
            if source.is_dir():
                shutil.copytree(source, target, symlinks=True)
            else:
                shutil.copyfile(source, target)
            return target
        source = copy(cwd, "source") if root else Path(cwd)
        ro = {copy(path, "read-" + str(i)) if root else Path(path): value
              for i, (path, value) in enumerate(read_only.items())}
        rw = {copy(path, "write-" + str(i)): value for i, (path, value) in enumerate(writable.items())}
        try:
            if root:
                staging.chmod(0o711)
                # Change children before their parent, and mode before ownership:
                # brokers intentionally have CHOWN but no DAC_OVERRIDE/FOWNER.
                for parent, folders, files in os.walk(staging, topdown=False, followlinks=False):
                    for path in [*(Path(parent) / n for n in files), Path(parent)]:
                        if path == staging or path.is_symlink():
                            continue
                        path.chmod(0o700 if path.is_dir() else 0o600)
                        os.chown(path, uid, uid)
            yield source, ro, rw, ({"user": uid, "group": uid, "extra_groups": []} if root else {})
        finally:
            if root:
                # Reclaim only our own copies; cleanup never follows input links.
                from .scan_runtime import reclaim
                reclaim(staging)


def offline_runner(tool: str, args: list[str], cwd: str | Path, *,
                   read_only=None, writable=None, environment=None, timeout: float = 600,
                   max_output: int | None = None, check_cancelled=None, _probe=False) -> dict[str, str]:
    if PLATFORM != "linux":
        raise RendererError("Offline actions require Linux isolation", infrastructure=True)
    with _staged_identity(cwd, read_only or {}, writable or {}) as (source, ro, rw, privileges):
        original = str(Path(cwd).resolve())
        translated = [str(source) + str(arg)[len(original):]
                      if str(arg) == original or str(arg).startswith(original + os.sep) else str(arg)
                      for arg in args]
        command = sandbox_command(tool, translated, source, read_only=ro, writable=rw,
                                  environment=environment, probe=_probe, _identity_prepared=bool(privileges))
        return _execute(tool, command, privileges, timeout, max_output, check_cancelled)


def _execute(tool, command, privileges, timeout, max_output, check_cancelled):
    """Bound wall time and optional output budget; spool native output to disk."""
    if max_output is None:
        max_output = 64 * 1024 * 1024
    with child_seccomp() as policy:
        command[1:1] = ["--seccomp", str(policy.fileno())]
        process = subprocess.Popen(supervised_command(command, pass_fds=(policy.fileno(),)),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env={"PATH": "/usr/bin:/bin"}, start_new_session=True,
                                   pass_fds=(policy.fileno(),), **privileges)
    outputs = {name: tempfile.TemporaryFile() for name in ("stdout", "stderr")}
    output_size = 0
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            for name in outputs:
                selector.register(getattr(process, name), selectors.EVENT_READ, name)
            next_check = 0.0
            while selector.get_map() or process.poll() is None:
                now = time.monotonic()
                if check_cancelled and now >= next_check:
                    check_cancelled()
                    next_check = now + 1
                remaining = deadline - now
                if remaining <= 0:
                    raise RendererError("Offline action exceeded time limit",
                                        reason="time_limit_exceeded" if tool in SCANNERS else None)
                for key, _ in selector.select(min(remaining, 0.2)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    outputs[key.data].write(chunk)
                    output_size += len(chunk)
                    if max_output and output_size > max_output:
                        raise RendererError("Offline action exceeded output limit",
                                            reason="output_limit_exceeded" if tool in SCANNERS else None)
        for output in outputs.values():
            output.seek(0)
        if process.returncode:
            # Native stderr can contain user secrets; keep it out of persisted errors.
            diagnostic = outputs["stderr"].read().decode("utf-8", errors="replace")
            infrastructure = any(line.startswith("bwrap:") for line in diagnostic.splitlines())
            if tool in SCANNERS:
                reason = scanner_failure_reason(diagnostic)
                if infrastructure:
                    diagnostic = "\n".join(line for line in diagnostic.splitlines() if line.startswith("bwrap:"))
                raise RendererError(
                    scanner_failure_message(reason), infrastructure=infrastructure, reason=reason,
                    scanner_diagnostic=ScannerDiagnostic(tool, process.returncode, diagnostic),
                )
            raise RendererError("Worker isolation is unavailable; check the host AppArmor and seccomp profiles"
                                if infrastructure else "Offline tool failed; review the supplied inputs",
                                value_paths=() if infrastructure else missing_value_paths(diagnostic),
                                infrastructure=infrastructure,
                                reason=None if infrastructure else renderer_failure_reason(diagnostic))
        return {"stdout": outputs["stdout"].read().decode("utf-8", errors="strict"),
                "version": tool_version(tool)}
    except subprocess.TimeoutExpired as exc:
        raise RendererError("Offline action exceeded time limit",
                            reason="time_limit_exceeded" if tool in SCANNERS else None) from exc
    finally:
        # Let the dedicated supervisor kill and reap adopted descendants before
        # it exits. Killing it immediately would orphan bwrap's namespace init.
        try:
            process.terminate()
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        process.stdout.close()
        process.stderr.close()
        for output in outputs.values():
            output.close()


def child_seccomp():
    """Deny namespace and mount changes after bwrap setup, without writable /proc/sys.

    Architecture is checked before syscall IDs. clone3 gets ENOSYS so Go/libc
    can fall back to clone; clone permits threads but rejects namespace flags.
    Unknown architectures fail closed instead of running an unfiltered tool.
    """
    import tempfile
    architectures = {
        'x86_64': (0xC000003E, 56, 272, 308, 165, 166, 155),
        'aarch64': (0xC00000B7, 220, 97, 268, 40, 39, 41),
    }
    arch = architectures.get(platform.machine())
    if arch is None:
        raise RendererError('Unsupported renderer seccomp architecture')
    audit, clone, unshare, setns, mount, umount, pivot = arch
    # Classic BPF tuples: opcode, jump-if-true, jump-if-false, constant.
    instructions = [(0x20, 0, 0, 4), (0x15, 1, 0, audit),
                    (0x06, 0, 0, 0x80000000), (0x20, 0, 0, 0),
                    (0x45, 0, 1, 0x40000000), (0x06, 0, 0, 0x80000000)]
    for syscall in (unshare, setns, mount, umount, pivot):
        instructions += [(0x15, 0, 1, syscall), (0x06, 0, 0, 0x00050001)]
    instructions += [(0x15, 0, 1, 435), (0x06, 0, 0, 0x00050026),
                     (0x15, 0, 3, clone), (0x20, 0, 0, 16),
                     (0x45, 0, 1, 0x7E020000), (0x06, 0, 0, 0x00050001),
                     (0x06, 0, 0, 0x7FFF0000)]
    policy = tempfile.TemporaryFile()
    policy.write(b''.join(struct.pack('HBBI', *instruction) for instruction in instructions))
    policy.seek(0)
    return policy


def tool_version(tool: str) -> str:
    """Read build-generated metadata outside the untrusted source tree."""
    try:
        versions = json.loads(Path('/opt/discovery/tool-versions.json').read_text())
        return str(versions[tool])[:512]
    except (OSError, ValueError, KeyError, TypeError):
        return 'unavailable'


def helm_template(chart_root, *, source_root=None, release="cats", namespace="default",
                  values=(), set_values=(), include_crds=True, timeout=180,
                  check_cancelled=None, kube_version=None, api_versions=(), set_typed=(), max_output=None):
    """Render an exact chart + ordered inputs using the common offline policy.

    Stage only the chart and selected values. Never mount the scan working
    directory, which can also contain registry authentication and control files.
    Compatibility values must be explicit; no workflow-specific retry changes
    the meaning of a submitted chart.
    """
    chart = Path(chart_root).resolve(strict=True)
    source = Path(source_root).resolve(strict=True) if source_root else chart.parent
    if not chart.is_dir() or not (chart / "Chart.yaml").is_file() or chart == Path(chart.anchor):
        raise RendererError("Invalid Helm chart directory")
    if source_root and not chart.is_relative_to(source):
        raise RendererError("Chart is outside the action source")
    if not isinstance(release, str) or not re.fullmatch(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?", release) or len(release) > 53:
        raise RendererError("Invalid Helm release name")
    if not isinstance(namespace, str) or not re.fullmatch(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?", namespace) or len(namespace) > 63:
        raise RendererError("Invalid Helm namespace")
    with tempfile.TemporaryDirectory(prefix="cats-helm-") as directory:
        staging = Path(directory)
        shutil.copytree(chart, staging / "chart", symlinks=True)
        args = ["template", release, str(staging / "chart"), "--namespace", namespace]
        if include_crds:
            args.append("--include-crds")
        for i, value in enumerate(values):
            path = Path(value)
            if not path.is_absolute():
                path = source / path
            path = path.resolve(strict=True)
            if source_root and not path.is_relative_to(source):
                raise RendererError("Values file is outside the action source")
            target = staging / ("values-" + str(i) + ".yaml")
            shutil.copyfile(path, target)
            args += ["--values", str(target)]
        for override in set_values:
            if not isinstance(override, str) or "=" not in override:
                raise RendererError("Invalid Helm string override")
            args += ["--set-string", override]
        for override in set_typed:
            if not isinstance(override, str) or "=" not in override:
                raise RendererError("Invalid Helm typed override")
            args += ["--set", override]
        if kube_version:
            args += ["--kube-version", str(kube_version)]
        for version in api_versions:
            args += ["--api-versions", str(version)]
        return isolated_runner("helm", args, staging, timeout=timeout, max_output=max_output, check_cancelled=check_cancelled)


def render_action(tool, args, cwd, *, check_cancelled=None, include_crds=True, restrict_source=True, max_output=None):
    """Adapt native argument lists to the same source-only rendering action."""
    if tool != "helm":
        return isolated_runner(tool, args, cwd, max_output=max_output, check_cancelled=check_cancelled)
    if len(args) < 3 or args[0] != "template":
        raise RendererError("Expected Helm template release chart")
    options = {"release": args[1], "namespace": "default", "values": [],
               "set_values": [], "set_typed": [], "api_versions": [], "include_crds": include_crds}
    flags = {"--namespace": "namespace", "-n": "namespace", "--values": "values", "-f": "values",
             "--set-string": "set_values", "--set": "set_typed", "--kube-version": "kube_version",
             "--api-versions": "api_versions"}
    index = 3
    while index < len(args):
        flag = args[index]
        if flag == "--include-crds":
            options["include_crds"] = True
            index += 1
            continue
        if flag not in flags or index + 1 >= len(args):
            raise RendererError("Unsupported Helm rendering option")
        key, value = flags[flag], args[index + 1]
        if isinstance(options.get(key), list):
            options[key].append(value)
        else:
            options[key] = value
        index += 2
    # CLI acquisition may stage a downloaded chart in its own temporary directory.
    # Resolve relative values against the caller, then copy only the selected files.
    options["values"] = [Path(value) if Path(value).is_absolute() else Path(cwd) / value
                         for value in options["values"]]
    return helm_template(args[2], source_root=cwd if restrict_source else None,
                         check_cancelled=check_cancelled, max_output=max_output, **options)


def main(argv=None):
    """CLI adapter used by ordinary scans; the implementation is also imported."""
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", action="store_true")
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    options = parser.parse_args(argv)
    try:
        if options.probe:
            with tempfile.TemporaryDirectory(prefix="cats-probe-") as directory:
                offline_runner("helm", ["version", "--short"], directory, timeout=15, _probe=True)
            return 0
        args = options.arguments
        if args and args[0] == "helm":
            args = args[1:]
        result = render_action("helm", args, Path.cwd(), include_crds=False, restrict_source=False)
        sys.stdout.write(result["stdout"])
        return 0
    except (RendererError, OSError) as exc:
        # Never echo arbitrary native diagnostics or input values into job logs.
        sys.stderr.write(str(exc) if isinstance(exc, RendererError) else "Offline action input is unavailable")
        sys.stderr.write("\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
