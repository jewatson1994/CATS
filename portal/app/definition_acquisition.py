"""Standalone exact-definition chart acquisition; no Portal or database imports."""
from contextlib import ExitStack
from pathlib import Path, PurePosixPath
import os
import tempfile
import urllib.parse
import yaml
from fastapi import HTTPException
from .scan_acquisition import _helm_index_url, _fetch_public_url, _helm_request_detail, _download_public_chart
from .helm_archives import extract_chart
from .helm_downloads import close_downloads

def _discover_helm_repository(url: str, certificates: list[dict] | None = None) -> dict:
    """Fetch repository metadata only; chart packages are materialized separately."""
    raw_url = str(url or "").strip()
    parsed = urllib.parse.urlparse(raw_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(422, detail="Helm repository URL must use http or https")
    index_url = _helm_index_url(raw_url)
    data, final_url = _fetch_public_url(index_url, certificates)
    try:
        index = yaml.safe_load(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, yaml.YAMLError):
        index = None
    if not isinstance(index, dict) or not isinstance(index.get("entries"), dict):
        raise HTTPException(400, detail=f"Malformed Helm index: repository does not provide a valid index.yaml [{_helm_request_detail('repository index retrieval', index_url, final_url)}]")
    charts = []
    for chart_name, raw_versions in sorted(index["entries"].items(), key=lambda item: str(item[0])):
        versions = []
        for item in raw_versions if isinstance(raw_versions, list) else []:
            if not isinstance(item, dict) or not isinstance(item.get("urls"), list) or not item["urls"] or not isinstance(item["urls"][0], str):
                continue
            versions.append({
                "version": str(item.get("version") or ""),
                "app_version": str(item.get("appVersion") or ""),
                "created": str(item.get("created") or ""),
                "digest": str(item.get("digest") or ""),
                "url": urllib.parse.urljoin(final_url, item["urls"][0]),
            })
        if versions:
            charts.append({"name": str(chart_name), "versions": versions, "latest": versions[0]})
    if not charts:
        raise HTTPException(400, detail=f"Helm repository index contains no chart versions [{_helm_request_detail('chart selection', index_url, final_url)}]")
    return {
        "repository_url": raw_url,
        "index_url": final_url,
        "api_version": str(index.get("apiVersion") or ""),
        "generated": str(index.get("generated") or ""),
        "charts": charts,
    }


def _primary_chart_markers(source: dict[str, str]) -> list[str]:
    """Exclude chart dependencies nested below another chart root."""
    markers = {PurePosixPath(name) for name in source if PurePosixPath(name).name == "Chart.yaml"}
    return sorted(str(marker) for marker in markers if not any(
        parent / "Chart.yaml" in markers for parent in marker.parent.parents
    ))


def _chart_identity(source: dict[str, str]) -> tuple[str, str]:
    markers = _primary_chart_markers(source)
    if len(markers) != 1:
        raise HTTPException(422, detail="A Helm Chart artifact must contain exactly one chart root")
    try:
        metadata = yaml.safe_load(source[markers[0]]) or {}
    except yaml.YAMLError as exc:
        raise HTTPException(422, detail="Helm Chart.yaml is invalid") from exc
    if not isinstance(metadata, dict):
        raise HTTPException(422, detail="Helm Chart.yaml is invalid")
    name, version = str(metadata.get("name") or "").strip(), str(metadata.get("version") or "").strip()
    if not name or not version:
        raise HTTPException(422, detail="Helm Chart.yaml must declare name and version")
    return name, version


def _collect_helm_source_files(charts_dir: Path) -> dict[str, str]:
    """Collect editable text sources with bounded size and stable paths."""
    if not charts_dir.is_dir():
        return {}
    limit = int(os.getenv("CATS_ARTIFACT_SOURCE_MAX_BYTES", str(100 * 1024 * 1024)))
    total = 0
    files: dict[str, str] = {}
    allowed_names = {"Chart.yaml", "Chart.lock", "values.yaml", "values.yml"}
    allowed_suffixes = {".yaml", ".yml", ".tpl", ".txt"}
    for path in sorted(charts_dir.rglob("*")):
        if not path.is_file() or (path.name not in allowed_names and path.suffix.lower() not in allowed_suffixes):
            continue
        if path.stat().st_size + total > limit:
            raise HTTPException(413, detail="Retained Helm text sources exceed CATS_ARTIFACT_SOURCE_MAX_BYTES; scan archive size and retained-source size are separate limits")
        raw = path.read_bytes()
        total += len(raw)
        try:
            files[path.relative_to(charts_dir).as_posix()] = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            continue
    return files


def _retained_helm_sources(archives: list[tuple[bytes, str]], *, preserve_archives: bool = False) -> tuple[dict[str, str], int]:
    """Use the scanner's guarded archive staging to produce one retained snapshot."""
    if not archives:
        raise HTTPException(status_code=422, detail="No Helm chart archives were supplied")
    with ExitStack() as cleanup, tempfile.TemporaryDirectory(prefix="cats-artifact-helm-") as temporary:
        if not preserve_archives:
            cleanup.callback(close_downloads, archives)
        root = Path(temporary)
        for archive, filename in archives:
            extract_chart(archive, filename, root / "charts")
        charts_dir = root / "charts"
        source = _collect_helm_source_files(charts_dir)
        if not source:
            raise HTTPException(status_code=422, detail="Helm source could not be retained within the configured source-size policy")
        chart_count = len(_primary_chart_markers(source))
        return source, chart_count


def acquire_component(component, certificates):
    """Resolve one normalized declaration through the shared guarded Helm path."""
    if component["source_type"] == "helm":
        catalog = _discover_helm_repository(component["repository"], certificates)
        entry = next((item for item in catalog.get("charts", []) if item.get("name") == component["chart_name"]), None)
        if entry is None:
            raise ValueError(f"Requested chart missing [{_helm_request_detail('chart selection', component['repository'])}]")
        requested = component["version"]
        version = ((entry or {}).get("latest") if requested == "latest" else
                   next((v for v in (entry or {}).get("versions", []) if str(v.get("version")) == requested), None))
        if not version or not version.get("url") or not version.get("version") or str(version["version"]) == "latest":
            raise ValueError(f"Requested chart version missing from repository catalog [{_helm_request_detail('chart selection', component['repository'])}]")
        source_url = version["url"]
        expected_version = str(version.get("version") or "")
    else:
        source_url = component["reference"]
    archives = _download_public_chart(source_url, certificates)
    try:
        files, count = _retained_helm_sources(archives, preserve_archives=True)
        actual_name, actual_version = _chart_identity(files)
        expected = expected_version if component["source_type"] == "helm" else component["version"]
        if count != 1 or not actual_version or (expected != "latest" and actual_version != expected) or (
            actual_name != component["chart_name"]
        ):
            raise ValueError("Retrieved chart identity or exact version did not match the declaration")
        return source_url, files, actual_name, actual_version, archives
    except BaseException:
        close_downloads(archives)
        raise


def _chart_app_version(files):
    """Retain chart application version separately from the Helm chart version."""
    markers = [(name, files[name]) for name in _primary_chart_markers(files)]
    if len(markers) != 1:
        return None
    try:
        chart = yaml.safe_load(markers[0][1])
    except (yaml.YAMLError, TypeError, UnicodeDecodeError):
        return None
    return str(chart.get("appVersion")) if isinstance(chart, dict) and chart.get("appVersion") is not None else None
