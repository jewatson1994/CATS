"""Stdlib-only regression: python3 portal/tests/test_action_supervisor.py.

The Linux tests intentionally run without an init process or Docker so image
entrypoint overrides cannot hide regressions in per-action process ownership.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import action_supervisor, rendering


HERE = str(Path(__file__).resolve())


def orphan_tree(mode, record=None):
    """Emulate a bwrap monitor exiting before a detached namespace init."""
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        os.setsid()
        grandchild = os.fork()
        if grandchild:
            os.write(write_fd, json.dumps([os.getpid(), grandchild]).encode())
            os._exit(0)
        os.close(write_fd)
        time.sleep(60)
        os._exit(0)
    os.close(write_fd)
    descendants = json.loads(os.read(read_fd, 4096))
    os.close(read_fd)
    os.waitpid(child, 0)
    message = json.dumps([os.getpid(), *descendants])
    if record:
        Path(record).write_text(message)
    print(message, flush=True)
    print("native stderr", file=sys.stderr, flush=True)
    if mode == "hold":
        time.sleep(60)
    elif mode == "signal":
        os.kill(os.getpid(), signal.SIGUSR1)
    else:
        os._exit(int(mode))


def wrapper():
    command = action_supervisor.supervised_command([sys.executable, HERE, "--orphan-tree", "hold"])
    child = subprocess.Popen(command, stdout=subprocess.PIPE, text=True)
    print(json.dumps({"supervisor": child.pid, "tree": json.loads(child.stdout.readline())}), flush=True)
    time.sleep(60)


def parent_death_harness():
    # Keep the supervisor's eventual zombie inside this disposable harness,
    # rather than changing the test runner's process-wide subreaper setting.
    assert action_supervisor._configure(os.getppid())
    parent = subprocess.Popen([sys.executable, HERE, "--wrapper"], stdout=subprocess.PIPE, text=True)
    record = json.loads(parent.stdout.readline())
    parent.kill()
    parent.wait()
    _, status = os.waitpid(record["supervisor"], 0)
    assert os.waitstatus_to_exitcode(status) == 128 + signal.SIGTERM
    assert all(not Path(f"/proc/{pid}").exists() for pid in record["tree"])


class SupervisorCommandTests(unittest.TestCase):
    def test_helper_is_absolute_and_preserves_inherited_descriptors(self):
        command = ["/usr/bin/bwrap", "--seccomp", "17", "--", "/tool", "version"]
        wrapped = action_supervisor.supervised_command(command, pass_fds=(17,))
        self.assertEqual(wrapped[:2], [sys.executable, "-I"])
        self.assertTrue(Path(wrapped[2]).is_absolute())
        self.assertEqual(wrapped[3:8], ["--parent-pid", str(os.getpid()), "--pass-fd", "17", "--"])
        self.assertEqual(wrapped[8:], command)

    def test_supervision_failure_is_an_infrastructure_error(self):
        with mock.patch.object(action_supervisor, "supervise", side_effect=OSError), \
                mock.patch.object(sys, "stderr") as stderr:
            result = action_supervisor.main(["--parent-pid", "1", "--", "secret-command"])
        self.assertEqual(result, 125)
        message = "".join(call.args[0] for call in stderr.write.call_args_list)
        self.assertIn("bwrap:", message)
        self.assertNotIn("secret-command", message)

    def test_unreadable_children_fail_before_launching_native_code(self):
        libc = mock.Mock()
        libc.prctl.return_value = 0
        with mock.patch.object(sys, "platform", "linux"), \
                mock.patch.object(action_supervisor.ctypes, "CDLL", return_value=libc), \
                mock.patch.object(action_supervisor, "_child_pids", side_effect=OSError), \
                mock.patch.object(signal, "SIGHUP", 1, create=True), \
                mock.patch.object(signal, "signal"), \
                mock.patch.object(action_supervisor.subprocess, "Popen") as spawn:
            with self.assertRaises(OSError):
                action_supervisor.supervise(["native-tool"], parent_pid=os.getppid())
        spawn.assert_not_called()


@unittest.skipUnless(sys.platform == "linux", "requires Linux child subreapers and /proc")
class SupervisorLinuxTests(unittest.TestCase):
    def launch(self, mode, **kwargs):
        return subprocess.Popen(action_supervisor.supervised_command(
            [sys.executable, HERE, "--orphan-tree", mode]),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, **kwargs)

    def assert_reaped(self, pids):
        self.assertTrue(all(not Path(f"/proc/{pid}").exists() for pid in pids),
                        f"action descendants were not reaped: {pids}")

    def test_repeated_probes_reap_detached_descendants_and_keep_exit_status(self):
        for index in range(32):
            expected = 0 if index % 2 == 0 else 23
            process = self.launch(str(expected))
            stdout, stderr = process.communicate(timeout=10)
            self.assertEqual(process.returncode, expected)
            self.assertEqual(stderr, "native stderr\n")
            self.assert_reaped(json.loads(stdout))

    def test_sigterm_reaps_active_tree(self):
        process = self.launch("hold")
        pids = json.loads(process.stdout.readline())
        process.terminate()
        process.communicate(timeout=10)
        self.assertEqual(process.returncode, 128 + signal.SIGTERM)
        self.assert_reaped(pids)

    def test_tool_signal_exit_is_preserved(self):
        process = self.launch("signal")
        stdout, _ = process.communicate(timeout=10)
        self.assertEqual(process.returncode, 128 + signal.SIGUSR1)
        self.assert_reaped(json.loads(stdout))

    def test_parent_death_cleans_up_supervisor_and_detached_tree(self):
        result = subprocess.run([sys.executable, HERE, "--parent-death-harness"],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_seccomp_descriptor_reaches_action(self):
        with tempfile.TemporaryFile() as policy:
            policy.write(b"test policy")
            policy.seek(0)
            fd = policy.fileno()
            command = action_supervisor.supervised_command(
                [sys.executable, "-c", f"import os; print(os.read({fd}, 64).decode())"], pass_fds=(fd,))
            result = subprocess.run(command, pass_fds=(fd,), capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "test policy\n")

    def test_runner_timeout_cancel_and_output_limit_reap_before_returning(self):
        class Cancelled(Exception):
            pass

        def fake_bwrap(command, **kwargs):
            # The fixture is Python rather than bwrap; remove only the two
            # bwrap seccomp arguments that _execute supplies, keeping the fd.
            self.assertEqual(command[1], "--seccomp")
            return action_supervisor.supervised_command([command[0], *command[3:]], **kwargs)

        for cause in ("timeout", "cancel", "output"):
            with self.subTest(cause=cause), tempfile.TemporaryDirectory() as directory:
                record = Path(directory) / "pids.json"

                def cancel():
                    if record.exists():
                        raise Cancelled()

                with mock.patch.object(rendering, "supervised_command", side_effect=fake_bwrap):
                    with self.assertRaises(Cancelled if cause == "cancel" else rendering.RendererError):
                        rendering._execute("helm", [sys.executable, HERE, "--orphan-tree", "hold", str(record)],
                            {}, 1.5 if cause == "timeout" else 10,
                            1 if cause == "output" else 1024, cancel if cause == "cancel" else None)
                self.assert_reaped(json.loads(record.read_text()))


if __name__ == "__main__":
    if sys.argv[1:2] == ["--orphan-tree"]:
        orphan_tree(*sys.argv[2:])
    elif sys.argv[1:2] == ["--wrapper"]:
        wrapper()
    elif sys.argv[1:2] == ["--parent-death-harness"]:
        parent_death_harness()
    else:
        unittest.main()
