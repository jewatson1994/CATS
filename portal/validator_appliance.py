"""Supervise both validator listeners without passing secrets in arguments."""

import os
import signal
import subprocess
import sys
import time


def main() -> int:
    stopping = False
    children: list[subprocess.Popen] = []

    def stop(_signal, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    os.umask(0o077)
    result = 0
    try:
        for module in ("validator_server", "validator_admin_server"):
            if stopping:
                break
            children.append(subprocess.Popen([sys.executable, "-m", module]))
        while not stopping:
            if any(child.poll() is not None for child in children):
                result = 1
                break
            time.sleep(0.2)
    finally:
        for child in children:
            if child.poll() is None:
                child.terminate()
        deadline = time.monotonic() + 20
        for child in children:
            try:
                child.wait(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
    return result


if __name__ == "__main__":
    raise SystemExit(main())
