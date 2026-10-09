"""Linux scanner supervisor: parent death kills the whole scanner process group."""
import ctypes
import os
import signal
import subprocess
import sys

def main():
    parent = int(sys.argv[1])
    if sys.platform == "linux":
        def terminate(*_):
            os.killpg(os.getpgrp(), signal.SIGKILL)
        signal.signal(signal.SIGTERM, terminate)
        if ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGTERM, 0, 0, 0):
            raise OSError(ctypes.get_errno(), "Cannot enforce scanner parent-death boundary")
        if os.getppid() != parent:
            terminate()
    return subprocess.call(sys.argv[2:])
if __name__ == "__main__":
    raise SystemExit(main())
