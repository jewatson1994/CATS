"""Value-free source diagnostics shared by planning, workers and delivery."""
from __future__ import annotations

from copy import deepcopy
from pathlib import PurePosixPath
import io
import json
import re
import tarfile
from zipfile import BadZipFile, ZipFile

import yaml

SENSITIVE = {"password", "passwd", "token", "clientsecret", "apikey", "privatekey", "credential", "secretkey", "secretaccesskey", "accesstoken", "authtoken"}
PLACEHOLDERS = {"", "null", "none", "~", "changeme", "change-me", "replace-me", "your-token", "your-password", "example", "placeholder", "<password>", "<token>", "<secret>"}
RESOLUTION = "Move literal credentials to an external Secret reference and reassess, or explicitly exclude the entire affected chart from this partial candidate. Original assessment evidence is retained."


class SourceSafetyError(ValueError):
    def __init__(self, diagnostics):
        super().__init__("Source requires secret review; inspect the sanitized source diagnostics")
        self.diagnostics = diagnostics


def _label(value):
    # Labels are addresses only; suppress unusual names that could themselves carry credentials.
    value = str(value)
    return value if len(value) <= 240 and re.fullmatch(r"[\w./\[\]{}$ -]+", value) else "[redacted address]"


def _empty(value):
    return value is None or isinstance(value, bool) or value == 0 or str(value).strip().lower() in PLACEHOLDERS


def _sensitive(key):
    normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
    return normalized in SENSITIVE or normalized.endswith(("password", "passwd", "clientsecret", "apikey", "privatekey", "accesstoken", "secretaccesskey"))


def _template_safe(expression):
    expression = expression.strip("{}- ")
    # Never let a reference elsewhere in the expression disguise a literal value.
    # Only quote strings used as lookup/index/helper addresses or empty fallbacks.
    for segment in expression.split("|"):
        literals = [match[1] for match in re.findall(r'(["\'`])(.*?)\1', segment)]
        if not literals:
            continue
        verb = segment.strip().split()[0].lstrip("(")
        if verb in {"default", "coalesce"}:
            if any(not _empty(value) for value in literals):
                return False
        elif verb in {"include", "template"}:
            if len(literals) != 1:
                return False
        elif verb == "lookup" or (verb == "index" and ".Values" in segment):
            pass
        elif any(not _empty(value) for value in literals):
            return False
    return bool(re.search(r"(?:\.Values\b|\.Release\b|\.Capabilities\b|\$[\w]+|\blookup\b|\binclude\b|\btemplate\b|\brandAlphaNum\b)", expression))


def _safe(value):
    if _empty(value):
        return True
    if isinstance(value, dict):
        if not value:
            return True
        if set(value) == {"valueFrom"}:
            return _safe(value["valueFrom"]) and isinstance(value["valueFrom"], dict)
        if len(value) == 1 and set(value) <= {"secretKeyRef", "configMapKeyRef"}:
            reference = next(iter(value.values()))
            return (isinstance(reference, dict) and {"name", "key"} <= set(reference) <= {"name", "key", "optional"}
                    and isinstance(reference["name"], str) and isinstance(reference["key"], str)
                    and isinstance(reference.get("optional", False), bool))
        return False
    if not isinstance(value, str):
        return False
    return value.strip() == "CATS_TEMPLATE_REFERENCE" or bool(re.fullmatch(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}", value.strip())) or bool(re.fullmatch(r"(?:secret|vault)://[\w/.-]+", value.strip()))


def chart_root(path, files):
    path = str(path).replace("\\", "/")
    roots = sorted({str(PurePosixPath(name).parent) for name in files if str(name).endswith("Chart.yaml")}, key=len)
    # A subchart is required by its parent: never remove only a dependency.
    return next((root for root in roots if root == "." or path.startswith(root + "/")), ".")


def source_diagnostics(files):
    diagnostics = []
    for filename, content in sorted(files.items()):
        if not isinstance(content, str):
            raise SourceSafetyError([{"chart": _label(chart_root(filename, files)), "file": _label(filename), "path": "$", "reason": "unsupported_source_encoding", "resolution": RESOLUTION}])
        root = chart_root(filename, files)
        seen = set()

        def report(path, reason):
            address = _label(path)
            if (address, reason) not in seen:
                diagnostics.append({"chart": _label(root), "file": _label(filename), "path": address, "reason": reason, "resolution": RESOLUTION})
                seen.add((address, reason))

        if re.search(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----", content):
            report("$", "private_key")
        # Mask complete template expressions before parsing YAML; never return parser errors/snippets.
        masked = re.sub(r"(?m)^[ \t]*{{-?\s*(?:if|else|end|range|with|define|\$\w+\s*:=)\b[^\n]*}}[ \t]*$", "", content)
        masked = re.sub(r"{{.*?}}", lambda match: "CATS_TEMPLATE_REFERENCE" if _template_safe(match[0]) else "CATS_TEMPLATE_REVIEW", masked, flags=re.S)

        def visit(node, path="$", secret=False, depth=0, ancestors=()):
            if depth > 64 or id(node) in ancestors:
                report(path, "unsupported_recursive_source")
                return
            if isinstance(node, dict):
                is_secret = node.get("kind") == "Secret"
                for key, value in node.items():
                    current = f"{path}.{key}"
                    sensitive = _sensitive(key)
                    data = secret or (is_secret and key in {"data", "stringData"})
                    if (sensitive or data) and not isinstance(value, (dict, list)) and not _safe(value):
                        report(current, "literal_secret_data" if data else "literal_credential")
                    if isinstance(value, (dict, list)):
                        if not ((sensitive or data) and _safe(value)):
                            visit(value, current, data or sensitive, depth + 1, (*ancestors, id(node)))
                if _sensitive(node.get("name", "")) and "value" in node and not _safe(node["value"]):
                    report(path + ".value", "literal_credential")
            elif isinstance(node, list):
                for index, value in enumerate(node):
                    visit(value, f"{path}[{index}]", secret, depth + 1, (*ancestors, id(node)))
            elif secret and not _safe(node):
                report(path, "literal_secret_data")

        try:
            for document in yaml.safe_load_all(masked):
                visit(document)
        except yaml.YAMLError:
            # Helm control structures can prevent YAML parsing. Scan key/value lines without echoing values.
            in_secret = bool(re.search(r"(?m)^\s*kind:\s*Secret\s*$", masked))
            for number, line in enumerate(masked.splitlines(), 1):
                match = re.match(r"\s*([\w.-]+)\s*[:=]\s*(.*?)\s*$", line)
                if not match:
                    continue
                key, value = match.groups()
                if _sensitive(key) and not _safe(value.strip("\"'")):
                    report(f"{key}[line {number}]", "literal_credential")
            if in_secret:
                # Unparseable Secret documents require review rather than guessing away literal content.
                report("$", "unresolved_secret_template")
        # dotenv is valid YAML as a scalar; inspect assignments independently of its filename.
        for number, line in enumerate(content.splitlines(), 1):
            match = re.match(r"\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$", line)
            if match and _sensitive(match[1]) and not _safe(match[2].strip("\"'")):
                report(f"{match[1]}[line {number}]", "literal_credential")
    return diagnostics


def assert_sources_safe(files):
    diagnostics = source_diagnostics(files)
    if diagnostics:
        raise SourceSafetyError(diagnostics)


def protect_plan(plan, files):
    diagnostics = source_diagnostics(files)
    blocked = sorted({chart_root(row["file"], files) for row in diagnostics})
    plan["source_safety"] = {"status": "requires_review" if diagnostics else "safe", "diagnostics": diagnostics,
                             "blocked_charts": blocked, "resolution": RESOLUTION, "partial": bool(blocked)}
    def affected(row):
        mapping = row.get("source_mapping") or {}
        path = mapping.get("values_file") or mapping.get("template") or mapping.get("source_file") or row.get("original_file")
        return bool(blocked) and ("." in blocked or (path and chart_root(path, files) in blocked))
    for row in plan.get("configuration_changes", []):
        for option in row.get("target_options", []):
            if affected(option):
                option.update(editable=False, reason=RESOLUTION, original_value=None)
                option["source_mapping"] = {key: value for key, value in (option.get("source_mapping") or {}).items() if key != "original_value"}
        if affected(row):
            row.update(editable=False, classification="REVIEW REQUIRED", reason=RESOLUTION,
                       source_blocked=True, original_value=None)
            if not any(option.get("editable") for option in row.get("target_options", [])):
                row["category"] = "MANUAL_ONLY"
            row["source_mapping"] = {key: value for key, value in (row.get("source_mapping") or {}).items() if key != "original_value"}
    for row in plan.get("images", []):
        if affected(row):
            row["source_blocked"] = True
            row["source_mapping"] = {"ambiguous": True}
            row["reason"] = "Image patching remains available; chart rewriting is blocked by source secret review."
    plan["changed_artifacts"] = [row for row in plan.get("changed_artifacts", []) if chart_root(row.get("path", ""), files) not in blocked]
    return plan


def approved_payload(payload, safety, excluded):
    blocked = safety.get("blocked_charts", [])
    if sorted(excluded) != sorted(blocked):
        raise ValueError("Explicitly confirm exclusion of every blocked chart before partial remediation")
    result = deepcopy(payload)
    for key in ("helm_source_files", "source_files"):
        files = result.get(key) or {}
        result[key] = {name: content for name, content in files.items() if chart_root(name, files) not in blocked}
    remaining = result.get("helm_source_files") or result.get("source_files") or {}
    result["helm_values_files"] = [path for path in result.get("helm_values_files", []) if path in remaining]
    assert_sources_safe(remaining)
    return result


def assert_chart_archive_safe(data, _depth=0):
    if _depth > 8:
        raise ValueError("Chart dependency nesting exceeds inspection limit")
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            files = {}
            total = 0
            for member in archive.getmembers():
                total += member.size
                if total > 32 * 1024 * 1024 or member.issym() or member.islnk():
                    raise ValueError("Unsafe chart source archive")
                if member.isfile():
                    raw = archive.extractfile(member).read()
                    if member.name.endswith(".tgz"):
                        assert_chart_archive_safe(raw, _depth + 1)
                    else:
                        files[member.name] = raw.decode("utf-8")
            assert_sources_safe(files)
    except (tarfile.TarError, UnicodeError):
        raise ValueError("Chart source archive cannot be inspected safely") from None


def assert_source_tree_safe(files):
    text_files = {}
    for name, content in files.items():
        if name.endswith(".tgz"):
            assert_chart_archive_safe(content)
        else:
            try:
                text_files[name] = content.decode("utf-8") if isinstance(content, bytes) else content
            except UnicodeError:
                raise ValueError("Chart source cannot be inspected safely") from None
    assert_sources_safe(text_files)


def assert_candidate_safe(path):
    try:
        _inspect_candidate(path)
    except SourceSafetyError:
        raise
    except (BadZipFile, UnicodeError, ValueError):
        raise SourceSafetyError([{"chart": ".", "file": "[candidate archive]", "path": "$",
                                  "reason": "unsupported_source_archive", "resolution": RESOLUTION}]) from None


def _inspect_candidate(path):
    with ZipFile(path) as archive:
        files = {}
        total = 0
        deployment = {}
        if "manifest.json" in archive.namelist():
            if archive.getinfo("manifest.json").file_size > 64 * 1024 * 1024:
                raise ValueError("Candidate manifest exceeds inspection limit")
            manifest = json.loads(archive.read("manifest.json"))
            if not isinstance(manifest, dict) or not isinstance(manifest.get("deployment", {}), dict):
                raise ValueError("Candidate manifest cannot be inspected safely")
            deployment = manifest.get("deployment") or {}
        chart = str(deployment.get("chartPath") or "").rstrip("/")
        values = deployment.get("valuesFiles") or []
        if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
            raise ValueError("Candidate values references cannot be inspected safely")
        for entry in archive.infolist():
            if entry.is_dir() or entry.filename.startswith("images/"):
                continue
            total += entry.file_size
            if total > 64 * 1024 * 1024:
                raise ValueError("Candidate source inspection exceeds size limit")
            if entry.filename.endswith(".tgz"):
                assert_chart_archive_safe(archive.read(entry))
            elif (entry.filename.startswith("candidate/") or entry.filename.endswith(("rendered.yaml", "rendered-before.yaml", "rendered-after.yaml"))
                  or (chart and (chart == "." or entry.filename.startswith(chart + "/"))) or entry.filename in values):
                try:
                    files[entry.filename] = archive.read(entry).decode("utf-8")
                except UnicodeError:
                    raise ValueError("Candidate source cannot be inspected safely") from None
        assert_sources_safe(files)
