"""Bounded, transactional chart extraction from a seekable upload spool."""
from io import BytesIO
import os
from pathlib import Path, PurePosixPath
import shutil
import tarfile
import tempfile
from zipfile import ZipFile, BadZipFile


def limit(name: str, default: int) -> int:
    value = int(os.getenv(name, str(default)))
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    return value


def compressed_limit() -> int:
    return limit("CATS_PUBLIC_MAX_CHART_BYTES", 512 * 1024 * 1024)


def extract_chart(archive, filename: str, charts_dir: Path) -> None:
    stream = BytesIO(archive) if isinstance(archive, bytes) else archive
    stream.seek(0, 2)
    if stream.tell() > compressed_limit():
        raise ValueError("Helm chart exceeds configured compressed archive limit")
    stream.seek(0)
    expanded_limit = limit("CATS_PUBLIC_MAX_CHART_EXPANDED_BYTES", 1024 * 1024 * 1024)
    member_limit = limit("CATS_PUBLIC_MAX_CHART_MEMBERS", 10000)
    charts_dir.mkdir(parents=True, exist_ok=True)
    seen = set()
    expanded = 0
    count = 0

    def validate(name, size):
        nonlocal expanded, count
        count += 1
        expanded += size
        if count > member_limit:
            raise ValueError("Helm chart exceeds configured archive member limit")
        if expanded > expanded_limit:
            raise ValueError("Helm chart exceeds configured expanded archive limit")
        path = PurePosixPath(name)
        if (not name or "\\" in name or ":" in name or path.is_absolute()
                or ".." in path.parts or not path.parts):
            raise ValueError("Helm archive contains an unsafe path")
        normalized = str(path).casefold()
        if normalized in seen:
            raise ValueError("Helm archive contains duplicate paths")
        seen.add(normalized)
        return path

    # Nothing becomes scanner input until the entire archive is validated.
    with tempfile.TemporaryDirectory(prefix=".chart-", dir=charts_dir.parent) as temporary:
        root = Path(temporary)
        try:
            if filename.lower().endswith(".zip"):
                with ZipFile(stream) as bundle:
                    for member in bundle.infolist():
                        path = validate(member.filename, member.file_size)
                        kind = (member.external_attr >> 16) & 0o170000
                        if kind not in (0, 0o100000, 0o040000):
                            raise ValueError("Helm archive contains an unsafe link or special entry")
                        target = root / path
                        if member.is_dir():
                            target.mkdir(parents=True, exist_ok=True)
                        else:
                            target.parent.mkdir(parents=True, exist_ok=True)
                            with bundle.open(member) as source, target.open("wb") as output:
                                shutil.copyfileobj(source, output, 1024 * 1024)
            elif filename.lower().endswith((".tgz", ".tar.gz", ".tar")):
                with tarfile.open(fileobj=stream, mode="r|*") as bundle:
                    for member in bundle:
                        path = validate(member.name, member.size)
                        if not (member.isfile() or member.isdir()):
                            raise ValueError("Helm archive contains an unsafe link or special entry")
                        target = root / path
                        if member.isdir():
                            target.mkdir(parents=True, exist_ok=True)
                        else:
                            target.parent.mkdir(parents=True, exist_ok=True)
                            with bundle.extractfile(member) as source, target.open("wb") as output:
                                shutil.copyfileobj(source, output, 1024 * 1024)
            else:
                raise ValueError("Helm chart must be a .tgz, .tar.gz, .tar, or .zip archive")
            if not any(root.rglob("Chart.yaml")):
                raise ValueError("Helm archive does not contain a Chart.yaml")
            # Separate source roots prevent packages with the same chart name
            # from overwriting each other, preserving multi-instance discovery.
            destination = Path(tempfile.mkdtemp(prefix="package-", dir=charts_dir))
            for item in root.iterdir():
                shutil.move(str(item), str(destination / item.name))
        except (tarfile.TarError, BadZipFile, OSError, EOFError) as exc:
            raise ValueError("Helm chart archive could not be read") from exc
