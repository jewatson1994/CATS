"""Self-contained, interactive HTML export for ephemeral CATS scan results."""
from __future__ import annotations

from datetime import datetime, timezone
from html import escape
import json
import re
from urllib.parse import quote, urlparse


def _text(value: object, fallback: str = "—") -> str:
    if value is None:
        return fallback
    rendered = str(value).strip()
    return rendered or fallback


def _safe_urls(*values: object) -> list[str]:
    urls: list[str] = []
    for value in values:
        candidates = value if isinstance(value, list) else [value]
        for candidate in candidates:
            raw = str(candidate or "").strip()
            parsed = urlparse(raw)
            if parsed.scheme in {"http", "https"} and parsed.netloc and raw not in urls:
                urls.append(raw)
    return urls


def _rows(payload: dict) -> list[dict]:
    rows: list[dict] = []
    for item in payload.get("findings") or []:
        if not isinstance(item, dict):
            continue
        evidence = item.get("evidence") if isinstance(item.get("evidence"), dict) else {}
        finding = _text(item.get("cve") or item.get("finding"), "Unknown")
        references = _safe_urls(item.get("urls"), item.get("references"), evidence.get("urls"), evidence.get("data_source"))
        if re.fullmatch(r"CVE-\d{4}-\d+", finding, re.IGNORECASE):
            references.insert(0, f"https://nvd.nist.gov/vuln/detail/{finding.upper()}")
        rows.append({
            "type": "Vulnerability",
            "finding": finding,
            "title": _text(item.get("title"), ""),
            "severity": _text(item.get("severity"), "Unknown"),
            "scanner": _text(item.get("scanner"), "Grype"),
            "image": _text(item.get("image")),
            "target": _text(item.get("package")),
            "details": _text(evidence.get("description"), "No description provided."),
            "remediation": _text(item.get("fixed_version"), "No fixed version reported."),
            "references": list(dict.fromkeys(references)),
        })
    for item in payload.get("policy_findings") or []:
        if not isinstance(item, dict):
            continue
        references = _safe_urls(item.get("urls"), item.get("references"), item.get("data_source"))
        rows.append({
            "type": "Configuration",
            "finding": _text(item.get("finding"), "Unknown"),
            "title": _text(item.get("title"), ""),
            "severity": _text(item.get("severity"), "Unknown"),
            "scanner": _text(item.get("scanner"), "Trivy"),
            "image": _text(item.get("target")),
            "target": _text(item.get("framework")),
            "details": _text(item.get("description"), "No description provided."),
            "remediation": _text(item.get("remediation"), "No remediation provided."),
            "references": references,
        })
    return rows


def _artifact_category(path: str) -> str:
    if path.startswith("sboms/"):
        return "SBOM"
    if path.startswith("trivy-results/"):
        return "Trivy"
    if path.startswith("results/"):
        return "Normalized result"
    if path.endswith(".log") or path.endswith(".txt"):
        return "Log"
    if path.endswith(".xlsx"):
        return "Workbook"
    if path.endswith((".tar.gz", ".tgz", ".zip")):
        return "Archive"
    return "Metadata"


def _size(value: object) -> str:
    size = max(0, int(value or 0))
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size if unit == 'B' else f'{size:.1f}'} {unit}"
        size /= 1024
    return "0 B"


def build_public_scan_report(payload: dict, job: dict, artifacts: list[dict] | None = None) -> str:
    payload = payload if isinstance(payload, dict) else {}
    job = job if isinstance(job, dict) else {}
    service = payload.get("service") if isinstance(payload.get("service"), dict) else {}
    rows = _rows(payload)
    vulnerabilities = sum(row["type"] == "Vulnerability" for row in rows)
    configurations = sum(row["type"] == "Configuration" for row in rows)
    images = sorted({row["image"] for row in rows if row["type"] == "Vulnerability" and row["image"] != "—"})
    for image in str(job.get("image_list") or "").splitlines():
        if image.strip() and image.strip() not in images:
            images.append(image.strip())
    missing = []
    for kind, values in (("Image", payload.get("skipped_images")), ("Chart", payload.get("skipped_charts"))):
        for value in values if isinstance(values, list) else ([values] if values else []):
            if isinstance(value, dict):
                missing.append(f"{kind}: {_text(value.get('item') or value.get('chart'))} — {_text(value.get('reason'))}")
            else:
                missing.append(f"{kind}: {_text(value)}")

    row_markup = []
    for index, row in enumerate(rows):
        search = " ".join(str(value) for key, value in row.items() if key != "references").casefold()
        row_markup.append(
            f'<tr data-index="{index}" data-type="{escape(row["type"])}" '
            f'data-severity="{escape(row["severity"])}" data-search="{escape(search, quote=True)}">'
            f'<td>{escape(row["type"])}</td>'
            f'<td><button class="finding-link" type="button" data-detail="{index}">{escape(row["finding"])}</button>'
            f'{f"<small>{escape(row["title"])}</small>" if row["title"] else ""}</td>'
            f'<td><span class="severity severity-{escape(row["severity"].casefold())}">{escape(row["severity"])}</span></td>'
            f'<td>{escape(row["scanner"])}</td><td><code>{escape(row["image"])}</code></td>'
            f'<td>{escape(row["target"])}</td><td>{escape(row["remediation"])}</td></tr>'
        )
    if not row_markup:
        row_markup.append('<tr class="empty-row"><td colspan="7">No findings were produced.</td></tr>')

    image_markup = "".join(
        f'<button type="button" class="chip" data-image="{escape(image, quote=True)}">{escape(image)}</button>'
        for image in images
    ) or '<span class="muted">No image references were reported.</span>'
    missing_markup = "".join(f"<li>{escape(item)}</li>" for item in missing) or "<li>No missing evidence.</li>"
    artifact_markup = []
    for artifact in artifacts or []:
        path = str(artifact.get("path") or "").replace("\\", "/").lstrip("/")
        if not path or ".." in path.split("/"):
            continue
        artifact_markup.append(
            f'<tr><td>{escape(_artifact_category(path))}</td><td><a href="{escape(quote(path, safe="/"), quote=True)}">'
            f'<code>{escape(path)}</code></a></td><td>{escape(_size(artifact.get("size")))}</td></tr>'
        )
    if not artifact_markup:
        artifact_markup.append('<tr class="empty-row"><td colspan="3">No additional artifacts were packaged.</td></tr>')
    generated = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    title = _text(service.get("name"), "CATS Scan Results")
    rows_json = json.dumps(rows, ensure_ascii=True).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")

    document = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>@@TITLE@@ · CATS Scan Overview</title>
<style>
:root{color-scheme:dark;--bg:#08100f;--panel:#0e1917;--panel2:#14211f;--line:#263735;--text:#eef6f3;--muted:#9fb1ac;--green:#72e0b4;--red:#ff776f;--amber:#e9bd68}*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:radial-gradient(circle at 80% -20%,#17312b 0,transparent 35%),var(--bg);color:var(--text);font:15px/1.5 Inter,system-ui,sans-serif}main{max-width:1400px;margin:auto;padding:42px 24px 80px}h1{font-size:clamp(34px,5vw,58px);line-height:1;margin:.3rem 0 1rem}.eyebrow{font-size:11px;letter-spacing:.16em;color:var(--green)}.muted,small{color:var(--muted)}.report-nav{position:sticky;top:0;z-index:5;display:flex;flex-wrap:wrap;gap:8px;margin:18px 0;padding:10px;background:#08100feb;border:1px solid var(--line)}.report-nav a{color:var(--text);text-decoration:none;padding:7px 10px;border:1px solid transparent}.report-nav a:hover{color:var(--green);border-color:var(--green)}.offline-note{padding:12px 14px;border:1px solid var(--amber);background:#e9bd6814;color:var(--muted)}.offline-note strong{color:var(--amber)}.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:24px 0}.metric{appearance:none;text-align:left;background:linear-gradient(140deg,var(--panel2),var(--panel));border:1px solid var(--line);color:var(--text);padding:18px;cursor:pointer}.metric:hover,.metric.active{border-color:var(--green)}.metric span{display:block;color:var(--muted)}.metric strong{font-size:30px}.panel{background:var(--panel);border:1px solid var(--line);margin-top:16px;scroll-margin-top:72px}.panel-head{padding:18px 20px;border-bottom:1px solid var(--line)}.panel-head h2{margin:0}.filters{display:grid;grid-template-columns:minmax(220px,1fr) 190px 190px auto;gap:10px;padding:14px 20px;border-bottom:1px solid var(--line)}input,select,button{font:inherit}input,select{width:100%;background:var(--bg);border:1px solid var(--line);color:var(--text);padding:10px 12px}.clear{background:transparent;border:1px solid var(--line);color:var(--text);padding:10px 14px;cursor:pointer}.clear:hover{border-color:var(--green)}.chips{display:flex;flex-wrap:wrap;gap:8px;padding:14px 20px}.chip{max-width:100%;overflow:hidden;text-overflow:ellipsis;background:var(--panel2);border:1px solid var(--line);color:var(--text);padding:7px 10px;cursor:pointer}.chip:hover{border-color:var(--green);color:var(--green)}.table-wrap{overflow:auto}table{border-collapse:collapse;width:100%;min-width:980px;text-align:left}th{font-size:11px;text-transform:uppercase;letter-spacing:.1em;color:var(--muted)}th,td{padding:13px 16px;border-bottom:1px solid var(--line);vertical-align:top}tbody tr:hover{background:var(--panel2)}td code{display:block;max-width:520px;white-space:normal;overflow-wrap:anywhere}td a{color:var(--green);text-decoration:none}td a:hover{text-decoration:underline}.finding-link{border:0;background:transparent;color:var(--green);padding:0;cursor:pointer;font-weight:800;text-align:left}.finding-link:hover{text-decoration:underline}.severity{display:inline-flex;padding:3px 8px;border:1px solid var(--line);border-radius:999px}.severity-critical,.severity-high{color:var(--red);border-color:var(--red)}.severity-medium{color:var(--amber);border-color:var(--amber)}.severity-low,.severity-negligible{color:var(--green);border-color:var(--green)}.evidence-list{margin:.6rem 0 0;padding:1rem 2.4rem}.empty-row td{text-align:center;color:var(--muted);padding:50px}dialog{width:min(720px,calc(100% - 32px));max-height:85vh;overflow:auto;color:var(--text);background:var(--panel);border:1px solid var(--line);padding:0}dialog::backdrop{background:#000a}.dialog-head{display:flex;justify-content:space-between;gap:16px;padding:18px 20px;border-bottom:1px solid var(--line)}.dialog-head h2{margin:0}.dialog-close{background:transparent;border:0;color:var(--muted);font-size:26px;cursor:pointer}.details{display:grid;grid-template-columns:140px 1fr;gap:10px 16px;padding:20px}.details dt{color:var(--muted)}.details dd{margin:0;overflow-wrap:anywhere}.details a{color:var(--green)}@media(max-width:760px){.report-nav{position:static}.filters{grid-template-columns:1fr}.details{grid-template-columns:1fr}.details dd{margin-bottom:8px}}
</style></head><body><main>
<p class="eyebrow">CATS · INTERACTIVE SCAN OVERVIEW</p><h1>@@TITLE@@</h1>
<p class="muted">Generated @@GENERATED@@ · Status: @@STATUS@@ · This report is self-contained and read-only.</p>
<p class="offline-note"><strong>Open this file after extracting the ZIP.</strong> Artifact links below are relative to this HTML file and work directly from the extracted directory.</p>
<nav class="report-nav" aria-label="Report sections"><a href="#summary">Summary</a><a href="#images">Images</a><a href="#findings">Findings</a><a href="#missing">Missing evidence</a><a href="#artifacts">Artifacts</a></nav>
<section class="metrics" id="summary" aria-label="Finding summary">
<button class="metric active" data-type-filter="all"><span>All findings</span><strong>@@TOTAL@@</strong></button>
<button class="metric" data-type-filter="Vulnerability"><span>Vulnerabilities</span><strong>@@VULNERABILITIES@@</strong></button>
<button class="metric" data-type-filter="Configuration"><span>Configuration</span><strong>@@CONFIGURATIONS@@</strong></button>
<button class="metric" data-show-missing><span>Missing evidence</span><strong>@@MISSING_COUNT@@</strong></button>
</section>
<section class="panel" id="images"><div class="panel-head"><h2>Images</h2><small>Select an image to filter its findings.</small></div><div class="chips">@@IMAGES@@</div></section>
<section class="panel" id="findings"><div class="panel-head"><h2>Findings</h2><small id="visible-count"></small></div>
<div class="filters"><input id="search" type="search" placeholder="Search finding, image, package, scanner…"><select id="type"><option value="all">All types</option><option>Vulnerability</option><option>Configuration</option></select><select id="severity"><option value="all">All severities</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Negligible</option><option>Unknown</option></select><button class="clear" id="clear" type="button">Clear filters</button></div>
<div class="table-wrap"><table><thead><tr><th>Type</th><th>Finding</th><th>Severity</th><th>Scanner</th><th>Image / target</th><th>Package / framework</th><th>Remediation</th></tr></thead><tbody>@@ROWS@@</tbody></table></div></section>
<section class="panel" id="missing"><div class="panel-head"><h2>Missing evidence</h2></div><ul class="evidence-list">@@MISSING@@</ul></section>
<section class="panel" id="artifacts"><div class="panel-head"><h2>Artifact directory</h2><small>Open raw evidence and generated reports from the extracted results directory.</small></div><div class="table-wrap"><table><thead><tr><th>Category</th><th>File</th><th>Size</th></tr></thead><tbody>@@ARTIFACTS@@</tbody></table></div></section>
<dialog id="detail"><div class="dialog-head"><h2 id="detail-title">Finding details</h2><button class="dialog-close" type="button" aria-label="Close">×</button></div><dl class="details"><dt>Type</dt><dd data-field="type"></dd><dt>Severity</dt><dd data-field="severity"></dd><dt>Scanner</dt><dd data-field="scanner"></dd><dt>Image / target</dt><dd data-field="image"></dd><dt>Package / framework</dt><dd data-field="target"></dd><dt>Details</dt><dd data-field="details"></dd><dt>Remediation</dt><dd data-field="remediation"></dd><dt>References</dt><dd id="references">—</dd></dl></dialog>
<script>
const findings=@@DATA@@;const search=document.querySelector('#search'),type=document.querySelector('#type'),severity=document.querySelector('#severity'),rows=[...document.querySelectorAll('tbody tr[data-index]')],visible=document.querySelector('#visible-count');function apply(){const q=search.value.trim().toLowerCase();let count=0;rows.forEach(row=>{const show=(!q||row.dataset.search.includes(q))&&(type.value==='all'||row.dataset.type===type.value)&&(severity.value==='all'||row.dataset.severity.toLowerCase()===severity.value.toLowerCase());row.hidden=!show;if(show)count++});visible.textContent=`${count} of ${rows.length} finding(s)`}search.addEventListener('input',apply);type.addEventListener('change',apply);severity.addEventListener('change',apply);document.querySelector('#clear').addEventListener('click',()=>{search.value='';type.value='all';severity.value='all';document.querySelectorAll('.metric').forEach(x=>x.classList.remove('active'));document.querySelector('[data-type-filter="all"]').classList.add('active');apply()});document.querySelectorAll('[data-type-filter]').forEach(button=>button.addEventListener('click',()=>{type.value=button.dataset.typeFilter;document.querySelectorAll('.metric').forEach(x=>x.classList.remove('active'));button.classList.add('active');document.querySelector('#findings').scrollIntoView({behavior:'smooth'});apply()}));document.querySelectorAll('[data-image]').forEach(button=>button.addEventListener('click',()=>{search.value=button.dataset.image;document.querySelector('#findings').scrollIntoView({behavior:'smooth'});apply()}));document.querySelector('[data-show-missing]').addEventListener('click',()=>document.querySelector('#missing').scrollIntoView({behavior:'smooth'}));const dialog=document.querySelector('#detail');document.querySelector('.dialog-close').addEventListener('click',()=>dialog.close());document.querySelectorAll('[data-detail]').forEach(button=>button.addEventListener('click',()=>{const item=findings[Number(button.dataset.detail)]||{};document.querySelector('#detail-title').textContent=item.finding||'Finding details';document.querySelectorAll('[data-field]').forEach(node=>node.textContent=item[node.dataset.field]||'—');const refs=document.querySelector('#references');refs.replaceChildren();if(item.references?.length){item.references.forEach((url,index)=>{const a=document.createElement('a');a.href=url;a.target='_blank';a.rel='noopener noreferrer';a.textContent=url;refs.append(a);if(index<item.references.length-1)refs.append(document.createElement('br'))})}else refs.textContent='—';dialog.showModal()}));apply();
</script></main></body></html>'''
    replacements = {
        "@@TITLE@@": escape(title),
        "@@GENERATED@@": escape(generated),
        "@@STATUS@@": escape(_text(job.get("status"), "unknown").title()),
        "@@TOTAL@@": str(len(rows)),
        "@@VULNERABILITIES@@": str(vulnerabilities),
        "@@CONFIGURATIONS@@": str(configurations),
        "@@MISSING_COUNT@@": str(len(missing)),
        "@@IMAGES@@": image_markup,
        "@@ROWS@@": "".join(row_markup),
        "@@MISSING@@": missing_markup,
        "@@ARTIFACTS@@": "".join(artifact_markup),
        "@@DATA@@": rows_json,
    }
    for marker, value in replacements.items():
        document = document.replace(marker, value)
    return document
