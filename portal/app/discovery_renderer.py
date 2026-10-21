"""Fail-closed, offline native rendering of untrusted deployment sources."""
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


class RendererError(RuntimeError):
    def __init__(self, message, *, value_paths=()):
        super().__init__(message)
        self.value_paths = list(value_paths)


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
PLATFORM = sys.platform


def _effective_uid() -> int:
    return os.geteuid()


def sandbox_command(tool: str, args: list[str], cwd: str | Path) -> list[str]:
    if PLATFORM != "linux" or _effective_uid() == 0:
        raise RendererError("Discovery requires the dedicated non-root Linux renderer")
    if tool not in TOOLS:
        raise RendererError("Unsupported discovery renderer")
    required = {"helm": "template", "compose": "config"}
    if tool in required and required[tool] not in args:
        raise RendererError("Only offline rendering commands are permitted")
    forbidden = ("--enable-helm", "--enable-alpha-plugins", "--enable-exec",
                 "--post-renderer", "--post-renderer-args", "--dependency-update")
    if any(str(arg).split("=", 1)[0] in forbidden for arg in args):
        raise RendererError("Discovery renderer extensions are disabled")
    executable, prefix = TOOLS[tool]
    if not Path("/usr/bin/bwrap").is_file() or not Path(executable).is_file():
        raise RendererError("Required isolated renderer is unavailable")
    source = Path(cwd).resolve(strict=True)
    if not source.is_dir() or source == Path("/"):
        raise RendererError("Invalid discovery source directory")
    # Only static native renderer binaries and this job's source are visible.
    # No worker /proc, environment, application files, database or upload volume.
    command = ["/usr/bin/bwrap", "--die-with-parent", "--new-session",
               "--unshare-all", "--unshare-user", "--cap-drop", "ALL",
               "--clearenv", "--ro-bind", executable, "/tool",
               "--ro-bind", str(source), "/source", "--tmpfs", "/tmp",
               "--proc", "/proc", "--dev", "/dev", "--chdir", "/source"]
    for key, value in {
        "HOME": "/tmp", "PATH": "/nonexistent", "TMPDIR": "/tmp",
        "HELM_PLUGINS": "/nonexistent", "HELM_CACHE_HOME": "/tmp/helm/cache",
        "HELM_CONFIG_HOME": "/tmp/helm/config", "HELM_DATA_HOME": "/tmp/helm/data",
        "KUBECONFIG": "/nonexistent", "DOCKER_CONFIG": "/nonexistent",
        "COMPOSE_DISABLE_ENV_FILE": "1", "COMPOSE_ANSI": "never",
    }.items():
        command += ["--setenv", key, value]
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
                    timeout: float = 60, max_output: int = 16 * 1024 * 1024) -> dict[str, str]:
    """Bound wall time and combined output; never fall back to host execution."""
    command = sandbox_command(tool, args, cwd)
    with child_seccomp() as policy:
        command[1:1] = ["--seccomp", str(policy.fileno())]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env={"PATH": "/usr/bin:/bin"}, start_new_session=True,
                                   pass_fds=(policy.fileno(),))
    outputs = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            for name in outputs:
                selector.register(getattr(process, name), selectors.EVENT_READ, name)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RendererError("Discovery renderer exceeded time limit")
                for key, _ in selector.select(min(remaining, 0.2)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    outputs[key.data].extend(chunk)
                    if sum(map(len, outputs.values())) > max_output:
                        raise RendererError("Discovery renderer exceeded output limit")
            process.wait(timeout=max(0.001, deadline - time.monotonic()))
        if process.returncode:
            # Native stderr can contain user secrets; keep it out of persisted errors.
            raise RendererError("Discovery rendering failed (including unavailable sandbox support)", value_paths=missing_value_paths(outputs["stderr"].decode("utf-8", errors="replace")))
        return {"stdout": outputs["stdout"].decode("utf-8", errors="strict"),
                "version": tool_version(tool)}
    except subprocess.TimeoutExpired as exc:
        raise RendererError("Discovery renderer exceeded time limit") from exc
    finally:
        # Also remove descendants if a renderer closes its pipes early.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        process.stdout.close()
        process.stderr.close()


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
