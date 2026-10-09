"""Existing bounded Helm acquisition helpers, independent of Portal initialization."""
from . import scan_runtime
import socket
import os, ssl, shutil, subprocess, tempfile, urllib.parse, urllib.request, urllib.error
from pathlib import Path
from contextlib import ExitStack
import yaml
from fastapi import HTTPException
from .helm_sources import normalize_chart_reference, oci_pull_arguments
from .helm_archives import compressed_limit
from .helm_downloads import DownloadedChart, copy_bounded, close_downloads, check_space
from .trusted_ca import ephemeral_trust
def _helm_request_detail(stage: str, requested: str, final: str | None = None) -> str:
    """Never retain credentials, signed queries, headers or response bodies."""
    def safe(value):
        try:
            parsed = urllib.parse.urlsplit(str(value))
            host = parsed.hostname or ""
            if ":" in host:
                host = f"[{host}]"
            if parsed.port:
                host += f":{parsed.port}"
            return urllib.parse.urlunsplit((parsed.scheme, host, parsed.path, "", ""))[:240].replace("\r", "").replace("\n", "")
        except ValueError:
            return "[invalid URL]"
    detail = f"stage={stage}; requested={safe(requested)}"
    if final:
        detail += f"; final={safe(final)}; redirected={'yes' if requested != final else 'no'}"
    return detail


def _helm_index_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(str(url or "").strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(422, detail="Helm repository URL must use http or https")
    path = parsed.path
    if not path.endswith("/index.yaml"):
        path = path.rstrip("/") + "/index.yaml"
    return urllib.parse.urlunsplit(parsed._replace(path=path, fragment=""))


def _fetch_public_stream(url: str, certificates: list[dict] | None = None):
    """Fetch into a bounded temporary file, preserving urllib TLS and redirects."""
    parsed = urllib.parse.urlparse(url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(status_code=400, detail="Chart URL must use http or https")
    max_bytes = compressed_limit()
    stage = "repository index retrieval" if parsed.path.endswith("/index.yaml") else "chart archive retrieval"
    final_url = None
    try:
        request = urllib.request.Request(url.strip(), headers={"User-Agent": "CATS/standalone-scanner"})
        context = ssl.create_default_context()
        for item in certificates or []:
            pem = str(item.get("pem") or "") if isinstance(item, dict) else ""
            if pem:
                context.load_verify_locations(cadata=pem)
        with urllib.request.urlopen(request, timeout=30, context=context) as response:
            content_length = int(response.headers.get("Content-Length") or 0)
            if content_length > max_bytes:
                raise HTTPException(status_code=413, detail="Helm chart archive is too large")
            final_url = response.geturl()
            data = copy_bounded(response, max_bytes)
    except HTTPException as exc:
        raise HTTPException(exc.status_code, detail=f"{exc.detail} [{_helm_request_detail(stage, url, final_url)}]") from exc
    except TimeoutError as exc:
        raise HTTPException(status_code=408, detail=f"Helm source acquisition timed out [{_helm_request_detail(stage, url, final_url)}]") from exc
    except urllib.error.HTTPError as exc:
        explanations = {
            401: "authentication required or denied",
            403: "request rejected; check repository authorization and proxy/firewall policy",
            404: "repository index or chart archive not found; check the source URL and exact version",
            429: "repository rate limit reached; retry later",
        }
        explanation = explanations.get(exc.code, "repository or intermediary returned an HTTP error")
        # Do not expose response bodies, headers, URL credentials or signed queries.
        exc.close()
        category = "redirect rejected by CATS policy" if 300 <= exc.code < 400 else explanation
        raise HTTPException(status_code=400, detail=f"Helm source request failed (HTTP {exc.code}): {category} [{_helm_request_detail(stage, url, exc.geturl())}]") from exc
    except urllib.error.URLError as exc:
        reason = exc.reason
        if isinstance(reason, (ssl.SSLError, ssl.SSLCertVerificationError)):
            raise HTTPException(
                status_code=400,
                detail=f"Helm source TLS certificate verification failed. Configure the issuing CA in CATS Trusted CA settings if this source is authorized. [{_helm_request_detail(stage, url)}]",
            ) from exc
        if isinstance(reason, (TimeoutError, socket.timeout)):
            raise HTTPException(status_code=408, detail=f"Helm source acquisition timed out [{_helm_request_detail(stage, url)}]") from exc
        raise HTTPException(status_code=400, detail=f"Helm source DNS/network failure: source is unreachable [{_helm_request_detail(stage, url)}]") from exc
    except ssl.SSLError as exc:
        raise HTTPException(400, detail=f"Helm source TLS certificate verification failed [{_helm_request_detail(stage, url)}]") from exc
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"Chart URL could not be downloaded [{_helm_request_detail(stage, url, final_url)}]") from exc
    return data, final_url


def _fetch_public_url(url: str, certificates: list[dict] | None = None) -> tuple[bytes, str]:
    """Compatibility metadata reader; archive transfers use the disk-backed path."""
    stream, final_url = _fetch_public_stream(url, certificates)
    try:
        return stream.read(), final_url
    finally:
        stream.close()


def _download_oci_chart(reference: str, certificates: list[dict] | None = None) -> list[tuple[DownloadedChart, str]]:
    """Pull one public OCI Helm chart using the bundled Helm executable."""
    from .oci_diagnostics import OciPullFailure
    helm = shutil.which("helm") or "/usr/local/bin/helm"
    if not Path(helm).exists() and shutil.which(helm) is None:
        raise OciPullFailure(reference, category="helm_execution_failure")
    max_bytes = compressed_limit()
    output = []
    try:
        with tempfile.TemporaryDirectory(prefix="cats-oci-chart-", dir=scan_runtime.environment().get("TMPDIR")) as destination:
            scan_runtime.readable(destination)
            check_space(destination, max_bytes)
            with ephemeral_trust(certificates) as (ca_file, trust_env):
                if ca_file:
                    scan_runtime.readable(ca_file.parent)
                    scan_runtime.readable(ca_file)
                command = [helm, "pull", *oci_pull_arguments(reference), "--destination", destination]
                if ca_file:
                    command.extend(["--ca-file", str(ca_file)])
                result = subprocess.run(
                    command, capture_output=True, text=True,
                    timeout=int(os.getenv("CATS_PUBLIC_HELM_PULL_TIMEOUT", "180")),
                    check=False, env={**scan_runtime.environment(), **trust_env},
                    **scan_runtime.privileges(),
                )
            check_space(destination)
            if result.returncode != 0:
                raise OciPullFailure(reference, exit_code=result.returncode,
                                     stderr=result.stderr or "", stdout=result.stdout or "",
                                     ca_file_used=bool(ca_file))
            archives = sorted(Path(destination).glob("*.tgz")) + sorted(Path(destination).glob("*.tar.gz"))
            if not archives:
                raise HTTPException(status_code=400, detail="Helm did not produce an OCI chart archive")
            for archive_path in archives:
                if archive_path.stat().st_size > max_bytes:
                    raise HTTPException(status_code=413, detail="Helm chart archive is too large")
                with archive_path.open("rb") as source:
                    data = copy_bounded(source, max_bytes)
                output.append((data, archive_path.name))
            return output
    except HTTPException:
        close_downloads(output)
        raise
    except subprocess.TimeoutExpired as exc:
        close_downloads(output)
        raise OciPullFailure(reference, category="timeout") from exc
    except (OSError, subprocess.SubprocessError) as exc:
        close_downloads(output)
        raise OciPullFailure(reference, category="helm_execution_failure" if isinstance(exc, OSError)
                             else "unknown_acquisition_failure") from exc
    except BaseException:
        close_downloads(output)
        raise


def _download_public_chart(url: str, certificates: list[dict] | None = None) -> list[tuple[DownloadedChart, str]]:
    """Download a chart archive or expand a Helm repository/index URL."""
    try:
        raw_url = normalize_chart_reference(url)
    except ValueError as exc:
        raise HTTPException(400, detail=str(exc)) from exc
    if raw_url.lower().startswith("oci://"):
        return _download_oci_chart(raw_url, certificates)
    parsed = urllib.parse.urlparse(raw_url)
    selector = parsed.fragment.strip()
    fetch_url = urllib.parse.urlunparse(parsed._replace(fragment=""))
    if selector or not parsed.path or parsed.path.endswith("/"):
        fetch_url = _helm_index_url(fetch_url)
    data, final_url = _fetch_public_stream(fetch_url, certificates)
    final_path = urllib.parse.urlparse(final_url).path.lower()
    signature = data.read(4)
    data.seek(0)
    if final_path.endswith((".tgz", ".tar.gz", ".tar", ".zip")) or signature.startswith((b"\x1f\x8b", b"PK\x03\x04")):
        return [(data, Path(final_path).name or "chart.tgz")]

    try:
        index_data, index_url = data.read(), final_url
    finally:
        data.close()
    try:
        index = yaml.safe_load(index_data.decode("utf-8-sig"))
    except (UnicodeDecodeError, yaml.YAMLError):
        index = None
    if not isinstance(index, dict) or not isinstance(index.get("entries"), dict):
        candidate_index_url = _helm_index_url(final_url)
        if candidate_index_url != final_url:
            try:
                index_data, index_url = _fetch_public_url(candidate_index_url, certificates)
                index = yaml.safe_load(index_data.decode("utf-8-sig"))
            except (UnicodeDecodeError, yaml.YAMLError):
                index = None
    if not isinstance(index, dict) or not isinstance(index.get("entries"), dict):
        raise HTTPException(status_code=400, detail=f"Malformed Helm index: Helm URL must point to a chart archive or Helm repository index.yaml [{_helm_request_detail('repository index retrieval', fetch_url, index_url)}]")

    entries = index["entries"]
    names = [selector] if selector else list(entries)
    if selector and selector not in entries:
        raise HTTPException(status_code=400, detail=f"Requested chart missing [stage=chart selection; {_helm_request_detail('chart selection', fetch_url, index_url)}]")
    archives: list[tuple[DownloadedChart, str]] = []
    with ExitStack() as cleanup:
        for chart_name in names:
            versions = entries.get(chart_name)
            if not isinstance(versions, list) or not versions:
                continue
            version = next((item for item in versions if isinstance(item, dict)
                            and isinstance(item.get("urls"), list) and item["urls"]
                            and isinstance(item["urls"][0], str)), None)
            if not version:
                continue
            archive_url = urllib.parse.urljoin(index_url, version["urls"][0])
            archive_data, archive_final_url = _fetch_public_stream(archive_url, certificates)
            cleanup.callback(archive_data.close)
            archive_name = Path(urllib.parse.urlparse(archive_final_url).path).name
            if not archive_name.lower().endswith((".tgz", ".tar.gz", ".tar", ".zip")):
                archive_name = f"{chart_name}-{version.get('version', 'latest')}.tgz"
            archives.append((archive_data, archive_name))
        cleanup.pop_all()
    if not archives:
        raise HTTPException(status_code=400, detail="Helm repository index contains no downloadable chart archives")
    return archives
