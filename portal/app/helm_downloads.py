"""Disk-backed ownership and bounded copying for acquired Helm archives."""
import os
import shutil
import tempfile

from fastapi import HTTPException


def check_space(path, incoming=0):
    reserve = int(os.getenv("CATS_PUBLIC_HELM_TEMP_RESERVE_BYTES", "0"))
    if reserve < 0:
        raise ValueError("CATS_PUBLIC_HELM_TEMP_RESERVE_BYTES must not be negative")
    if shutil.disk_usage(path).free < reserve + incoming:
        raise HTTPException(507, detail="Insufficient temporary disk space for Helm acquisition")


class DownloadedChart:
    """A private temporary file; consumers must close it after staging."""

    def __init__(self):
        check_space(tempfile.gettempdir())
        self.file = tempfile.TemporaryFile(mode="w+b", prefix="cats-chart-")

    def __getattr__(self, name):
        return getattr(self.file, name)

    def close(self):
        self.file.close()


def copy_bounded(source, maximum):
    target = DownloadedChart()
    try:
        total = 0
        while True:
            chunk = source.read(min(1024 * 1024, maximum - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise HTTPException(413, detail="Helm chart archive is too large")
            check_space(tempfile.gettempdir(), len(chunk))
            target.write(chunk)
        target.seek(0)
        return target
    except BaseException:
        target.close()
        raise


def close_downloads(archives):
    for archive, _name in archives:
        if isinstance(archive, DownloadedChart):
            archive.close()
