"""Reap one offline action's complete process tree, outside its sandbox.

This helper owns all of its children. Keeping waitpid(-1) here, rather than in
the threaded worker, cannot consume another job's subprocess exit status.
"""
from __future__ import annotations

import argparse
import ctypes
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def supervised_command(command, *, pass_fds=()):
    """Use the installed helper even when the caller changes cwd or identity."""
    return [sys.executable, "-I", str(Path(__file__).resolve()),
            "--parent-pid", str(os.getpid()),
            *[part for fd in pass_fds for part in ("--pass-fd", str(fd))],
            "--", *command]


def _configure(parent_pid):
    if sys.platform != "linux":
        raise RuntimeError("action supervision requires Linux")
    libc = ctypes.CDLL(None, use_errno=True)
    # prctl is variadic: explicitly provide all unsigned-long arguments.
    for option, value in ((36, 1), (1, signal.SIGTERM)):
        if libc.prctl(ctypes.c_int(option), ctypes.c_ulong(value),
                      ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0)):
            raise OSError(ctypes.get_errno(), "cannot configure action supervision")
    # Reject unsupported proc mounts before launching native code, not during
    # cleanup after a tool has already created descendants.
    _child_pids()
    # The parent may have died before PR_SET_PDEATHSIG was installed.
    return os.getppid() == parent_pid


def _child_pids():
    return [int(pid) for pid in Path(f"/proc/self/task/{os.getpid()}/children").read_text().split()]


def _kill_children():
    # Namespace init processes and tools can create their own sessions. Reap
    # and rescan our direct children until their descendants have been adopted.
    for child in _child_pids():
        try:
            os.kill(child, signal.SIGKILL)
        except ProcessLookupError:
            pass


def supervise(command, *, parent_pid, pass_fds=()):
    stopped = 0

    def stop(signum, _frame):
        nonlocal stopped
        stopped = signum

    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, stop)
    if not _configure(parent_pid) or stopped:
        return 128 + (stopped or signal.SIGTERM)

    child = subprocess.Popen(command, pass_fds=pass_fds, start_new_session=True)
    result = None
    while True:
        # After the monitor exits, no descendant may outlive the action. On
        # cancellation, terminate the monitor too; repeatedly kill adopted
        # children because bwrap's private PID namespace may be in a new group.
        if stopped or result is not None:
            if child.returncode is None:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            _kill_children()
        while True:
            try:
                pid, status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                return 128 + stopped if stopped else result
            if not pid:
                break
            if pid == child.pid:
                child.returncode = os.waitstatus_to_exitcode(status)
                result = child.returncode if child.returncode >= 0 else 128 - child.returncode
        time.sleep(0.01)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parent-pid", type=int, required=True)
    parser.add_argument("--pass-fd", type=int, action="append", default=[])
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("an action command is required")
    try:
        return supervise(command, parent_pid=args.parent_pid, pass_fds=tuple(args.pass_fd))
    except (OSError, RuntimeError):
        # Match the runner's infrastructure classification without retaining
        # supplied arguments, paths, or native tool stderr in persisted errors.
        print("bwrap: action process supervision is unavailable", file=sys.stderr)
        return 125


if __name__ == "__main__":
    raise SystemExit(main())
