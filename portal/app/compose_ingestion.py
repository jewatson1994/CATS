"""Offline Docker Compose ingestion; never invokes Docker or host commands.

Supports YAML anchors, ordered file overrides, !reset/!override, common Compose
unique-resource merges, profiles, supplied .env/env_file and shell-style variable
operators. Only bundle files supply variables (never the process environment).
Relative paths resolve against the first selected Compose file. Includes, extends,
remote inputs, multiline dotenv, label files, lifecycle hooks, model/provider
services and platform-specific scans require prior explicit
flattening with trusted tooling and are reported as incomplete. Runtime/build
behavior is never claimed to be validated. Values of environment, labels,
commands, healthchecks and build arguments are always redacted in retained data.
"""
from __future__ import annotations

import io
import math
import re
import stat
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

MAX_FILE = 4 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
MAX_FILES = 500
MAX_NODES = 30000
REDACTED = "[redacted]"
UNKNOWN = "[unresolved]"


class ComposeInputError(ValueError):
    """Safe fixed-text error suitable for display; never contains input values."""


def _relative(name: str) -> str:
    value = str(name).replace("\\", "/")
    path = PurePosixPath(value)
    if (not value or len(value) > 500 or path.is_absolute() or ".." in path.parts
            or ":" in value or any(ord(c) < 32 for c in value)
            or any(part.endswith((".", " ")) for part in path.parts)
            or any(re.match(r"(?i)^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)", part) for part in path.parts)):
        raise ComposeInputError("Unsafe or invalid bundle path.")
    return path.as_posix()


def _inside(root: Path, name: str) -> Path:
    name = _relative(name)
    root = root.resolve()
    candidate = root / name
    current = root
    for part in PurePosixPath(name).parts:
        current = current / part
        if current.is_symlink():
            raise ComposeInputError("Bundle links are not allowed.")
    if not candidate.resolve().is_relative_to(root):
        raise ComposeInputError("Bundle input leaves the supplied directory.")
    return candidate


def _read(root: Path, name: str) -> str:
    path = _inside(root, name)
    if not path.is_file():
        raise ComposeInputError("Required bundle input is missing.")
    if path.stat().st_size > MAX_FILE:
        raise ComposeInputError("Bundle input exceeds the per-file size limit.")
    try:
        return path.read_bytes().decode("utf-8-sig")
    except (OSError, UnicodeError):
        raise ComposeInputError("Bundle input must be readable UTF-8 text.") from None


def stage_uploads(root: Path, uploads: list[tuple[Any, str]]) -> dict:
    """Stage uploaded bytes/streams in root/.cats-compose; return root/files.

    Extraction is bounded and rejects links, devices, traversal, collisions and
    encrypted archives. No archive member is passed to extract()/extractall().
    Existing destinations are never overwritten. Errors contain no source data.
    """
    root = Path(root).resolve()
    destination = _inside(root, ".cats-compose")
    entries: dict[str, bytes] = {}
    total = 0

    def add(name: str, data: bytes):
        nonlocal total
        name = _relative(name)
        if name.casefold() in {key.casefold() for key in entries}:
            raise ComposeInputError("Duplicate bundle paths are not allowed.")
        total += len(data)
        if len(data) > MAX_FILE or total > MAX_TOTAL or len(entries) >= MAX_FILES:
            raise ComposeInputError("Compose bundle exceeds upload limits.")
        entries[name] = data

    try:
        if len(uploads) > MAX_FILES:
            raise ComposeInputError("Compose bundle exceeds upload limits.")
        for stream, filename in uploads:
            filename = _relative(filename)
            data = stream if isinstance(stream, bytes) else stream.read(MAX_TOTAL + 1)
            if len(data) > MAX_TOTAL:
                raise ComposeInputError("Compose bundle exceeds upload limits.")
            suffix = filename.lower()
            if suffix.endswith(".zip"):
                with zipfile.ZipFile(io.BytesIO(data)) as archive:
                    if len(archive.infolist()) > MAX_FILES:
                        raise ComposeInputError("Compose bundle exceeds upload limits.")
                    for member in archive.infolist():
                        _relative(member.filename)
                        mode = member.external_attr >> 16
                        if stat.S_ISLNK(mode) or (stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR)):
                            raise ComposeInputError("Archive links and special files are not allowed.")
                        if member.is_dir():
                            continue
                        if member.file_size > MAX_FILE or member.flag_bits & 1:
                            raise ComposeInputError("Archive member is oversized or encrypted.")
                        with archive.open(member) as source:
                            add(member.filename, source.read(MAX_FILE + 1))
            elif suffix.endswith((".tar", ".tgz", ".tar.gz")):
                with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
                    for number, member in enumerate(archive):
                        if number >= MAX_FILES:
                            raise ComposeInputError("Compose bundle exceeds upload limits.")
                        _relative(member.name)
                        if member.isdir():
                            continue
                        if not member.isfile() or member.size > MAX_FILE:
                            raise ComposeInputError("Archive links, special files and oversized members are not allowed.")
                        with archive.extractfile(member) as source:
                            add(member.name, source.read(MAX_FILE + 1))
            else:
                add(filename, data)
        # Validate every destination before performing any writes.
        targets = {name: _inside(destination, name) for name in entries}
        if any(path.exists() for path in targets.values()):
            raise ComposeInputError("Compose bundle destination already exists.")
        for name, path in targets.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as output:
                output.write(entries[name])
    except ComposeInputError:
        raise
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile, tarfile.TarError):
        raise ComposeInputError("Unable to read or stage the Compose bundle.") from None
    return {"root": destination, "files": sorted(entries)}


@dataclass
class _Tag:
    kind: str
    value: Any


class _Loader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        seen = set()
        for key, _ in node.value:
            if key.tag == "tag:yaml.org,2002:merge":
                continue
            if not isinstance(key, yaml.ScalarNode) or key.value in seen:
                raise ComposeInputError("Compose mappings require distinct scalar keys.")
            seen.add(key.value)
        return super().construct_mapping(node, deep=deep)

    def __init__(self, stream):
        super().__init__(stream)
        self.node_count = self.alias_count = self.level = 0

    def compose_node(self, parent, index):
        self.node_count += 1
        self.level += 1
        if self.check_event(yaml.AliasEvent):
            self.alias_count += 1
        if self.node_count > MAX_NODES or self.level > 50 or self.alias_count > 100:
            raise ComposeInputError("YAML complexity exceeds safe limits.")
        try:
            return super().compose_node(parent, index)
        finally:
            self.level -= 1


def _tag(loader, node):
    if isinstance(node, yaml.MappingNode):
        value = loader.construct_mapping(node, deep=True)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    else:
        value = loader.construct_scalar(node)
    return _Tag(node.tag[1:], value)


# Compose uses YAML 1.2; PyYAML's YAML 1.1 yes/no and sexagesimal numbers
# otherwise change perfectly valid image names and short port strings.
_Loader.yaml_implicit_resolvers = {
    key: [(tag, pattern) for tag, pattern in values
          if tag not in {"tag:yaml.org,2002:bool", "tag:yaml.org,2002:int", "tag:yaml.org,2002:timestamp"}]
    for key, values in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
_Loader.add_implicit_resolver("tag:yaml.org,2002:bool", re.compile(r"^(?:true|false|True|False|TRUE|FALSE)$"), list("tTfF"))
_Loader.add_implicit_resolver("tag:yaml.org,2002:int", re.compile(r"^[-+]?(?:0|[1-9][0-9_]*|0x[0-9a-fA-F_]+|0o[0-7_]+)$"), list("-+0123456789"))
_Loader.add_constructor("!reset", _tag)
_Loader.add_constructor("!override", _tag)


def _yaml(text: str):
    try:
        loader = _Loader(text)
        try:
            node = loader.get_single_node()
            expansion = 0
            def check_node(current, parents, depth):
                nonlocal expansion
                expansion += 1
                if expansion > MAX_NODES or depth > 50 or id(current) in parents:
                    raise ComposeInputError("YAML expansion exceeds safe limits.")
                children = ([child for pair in current.value for child in pair] if isinstance(current, yaml.MappingNode)
                            else current.value if isinstance(current, yaml.SequenceNode) else [])
                for child in children:
                    check_node(child, parents | {id(current)}, depth + 1)
            if node is not None:
                check_node(node, set(), 0)
            value = loader.construct_document(node) if node is not None else None
        finally:
            loader.dispose()
        count = 0

        def check(item, parents, depth):
            nonlocal count
            count += 1
            if count > MAX_NODES or depth > 50 or id(item) in parents:
                raise ComposeInputError("YAML expansion exceeds safe limits.")
            if isinstance(item, float) and not math.isfinite(item):
                raise ComposeInputError("Non-finite numeric values are not supported.")
            if isinstance(item, _Tag):
                check(item.value, parents | {id(item)}, depth + 1)
            elif isinstance(item, (dict, list)):
                for child in (item.values() if isinstance(item, dict) else item):
                    check(child, parents | {id(item)}, depth + 1)
                if isinstance(item, dict) and any(not isinstance(key, str) for key in item):
                    raise ComposeInputError("Compose mappings require string keys.")
        check(value, set(), 0)
        return value
    except ComposeInputError:
        raise
    except (yaml.YAMLError, ValueError, TypeError, RecursionError):
        raise ComposeInputError("Invalid or unsupported Compose YAML; verify syntax and supported tags.") from None


def _expand(text: str, env: dict, issue, depth=0) -> str:
    if depth > 20:
        issue("interpolation", "Variable expansion exceeds safe limits.")
        return UNKNOWN
    result, i = [], 0
    while i < len(text):
        if text[i] != "$":
            result.append(text[i]); i += 1; continue
        if text[i:i + 2] == "$$":
            result.append("$"); i += 2; continue
        if text[i:i + 2] == "${":
            end, level = i + 2, 1
            while end < len(text) and level:
                if text[end:end + 2] == "${":
                    level += 1; end += 2; continue
                if text[end] == "}":
                    level -= 1
                end += 1
            if level:
                issue("interpolation", "Malformed variable expression; supply a valid Compose expression.")
                return UNKNOWN
            expression = text[i + 2:end - 1]
            match = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-+?])(.*))?", expression, re.S)
            i = end
            if not match:
                issue("interpolation", "Unsupported variable expression; supply an explicitly resolved value.")
                result.append(UNKNOWN); continue
            name, operator, argument = match.groups()
        else:
            match = re.match(r"\$([A-Za-z_][A-Za-z0-9_]*)", text[i:])
            if not match:
                result.append("$"); i += 1; continue
            name, operator, argument = match[1], None, None
            i += len(match[0])
        present = name in env and (not operator or not operator.startswith(":") or env[name] != "")
        if operator and operator.endswith("-"):
            value = env[name] if present else _expand(argument, env, issue, depth + 1)
        elif operator and operator.endswith("+"):
            value = _expand(argument, env, issue, depth + 1) if present else ""
        elif operator and operator.endswith("?"):
            value = env[name] if present else UNKNOWN
            if not present:
                issue("required_variable", f"Deployment requires variable {name}, but it was not supplied. Runtime values may remain unresolved for image scanning.")
        else:
            value = env.get(name, UNKNOWN)
            if name not in env:
                issue("unresolved_variable", f"Variable {name} is unresolved in the uploaded inputs. Runtime values may remain unresolved for image scanning.")
        result.append(str(value))
    return "".join(result)


def _interpolate(value, env, issue):
    if isinstance(value, _Tag):
        return _Tag(value.kind, _interpolate(value.value, env, issue))
    if isinstance(value, dict):
        return {key: _interpolate(child, env, issue) for key, child in value.items()}
    if isinstance(value, list):
        return [_interpolate(child, env, issue) for child in value]
    return _expand(value, env, issue) if isinstance(value, str) else value


def _quoted_dotenv(value, issue):
    """Parse one physical line; only explicit common double-quote escapes decode.

    Single quotes stay literal, except escaped single quotes. Double quotes
    support escaped quotes, backslashes, and n/r/t. Other escapes are reported
    instead of silently reinterpreted. A closing quote may be followed only by
    whitespace and a comment; comment quotes never become part of the value.
    """
    quote, characters, index = value[0], [], 1
    while index < len(value):
        character = value[index]
        if character == quote:
            tail = value[index + 1:].strip()
            if tail and not tail.startswith("#"):
                issue("unsupported_dotenv", "Unexpected text after a quoted dotenv value; use a single-line assignment and optional comment.")
                return None
            return "".join(characters)
        if character == "\\":
            if index + 1 >= len(value):
                break
            escaped = value[index + 1]
            if quote == "'":
                if escaped == "'":
                    characters.append("'")
                    index += 2
                    continue
                characters.append(character)
                index += 1
                continue
            escapes = {"n": "\n", "r": "\r", "t": "\t", "\\": "\\", '"': '"'}
            if escaped not in escapes:
                issue("unsupported_dotenv", "Unsupported double-quoted dotenv escape; use common newline, carriage-return, tab, backslash or quote escapes, or a single-quoted literal.")
                return None
            characters.append(escapes[escaped])
            index += 2
            continue
        characters.append(character)
        index += 1
    issue("unsupported_dotenv", "Multiline or unterminated dotenv values require explicit single-line values.")
    return None


def _dotenv(text, env, issue, raw=False):
    result = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)(?:\s*=\s*(.*))?", line)
        if not match:
            issue("unsupported_dotenv", "Invalid or multiline dotenv input; supply one assignment per line."); continue
        key, value = match.groups()
        if value is None:
            result[key] = None; continue
        if raw:
            result[key] = value; continue
        quote = value[:1]
        if quote in ("'", '"'):
            value = _quoted_dotenv(value, issue)
            if value is None:
                continue
        else:
            value = re.split(r"\s+#", value, maxsplit=1)[0].rstrip()
        result[key] = value if quote == "'" else _expand(value, {**env, **result}, issue)
    return result


def _mapping(value):
    if isinstance(value, dict):
        return value
    if isinstance(value, list):
        return {str(entry).partition("=")[0]: str(entry).partition("=")[2] if "=" in str(entry) else None for entry in value}
    return {}


def _port(value):
    if isinstance(value, dict):
        return dict(value)
    spec, _, protocol = str(value).partition("/")
    parts = spec.rsplit(":", 2)
    if len(parts) == 1:
        return {"target": parts[0], "protocol": protocol or "tcp", "published": None}
    return {"target": parts[-1], "published": parts[-2], "host_ip": parts[0].strip("[]") if len(parts) == 3 else None, "protocol": protocol or "tcp"}


def _mount(value):
    if isinstance(value, dict):
        return dict(value)
    parts = str(value).split(":")
    # Compose Windows drive paths are kept explicitly unknown rather than split incorrectly.
    if re.match(r"^[A-Za-z]:", str(value)):
        return {"type": "bind", "source": UNKNOWN, "target": UNKNOWN, "unresolved": True}
    source = parts[0] if len(parts) > 1 else None
    return {"type": "bind" if source and (source.startswith((".", "/", "~")) or "/" in source) else "volume", "source": source, "target": parts[1] if len(parts) > 1 else parts[0], "read_only": len(parts) > 2 and "ro" in parts[2].split(",")}


def _resource_key(key, value):
    if key == "ports":
        entry = _port(value)
        return tuple(str(entry.get(k) or "") for k in ("host_ip", "target", "published", "protocol"))
    if key == "volumes":
        return _mount(value).get("target")
    return value.get("target", value.get("source")) if isinstance(value, dict) else value


def _merge(old, new, key=""):
    if isinstance(new, _Tag):
        return ({} if isinstance(new.value, dict) else [] if isinstance(new.value, list) else None) if new.kind == "reset" else _merge(None, new.value, key)
    if key in ("environment", "labels", "sysctls", "storage_opt", "extra_hosts"):
        return {**_mapping(old), **_mapping(new)}
    if isinstance(new, dict):
        base = dict(old) if isinstance(old, dict) else {}
        for field, value in new.items():
            base[field] = _merge(base.get(field), value, field)
        return base
    if isinstance(new, list):
        if key in ("command", "entrypoint", "test"):
            return list(new)
        base = list(old) if isinstance(old, list) else []
        if key in ("ports", "volumes", "secrets", "configs"):
            for item in new:
                match = next((i for i, prior in enumerate(base) if _resource_key(key, prior) == _resource_key(key, item)), None)
                if match is None:
                    base.append(item)
                else:
                    prior = base[match]
                    if isinstance(item, dict) and not isinstance(prior, dict):
                        prior = _mount(prior) if key == "volumes" else _port(prior) if key == "ports" else {"source": prior}
                    base[match] = _merge(prior, item) if isinstance(item, dict) else item
            return base
        return base + [item for item in new if key not in {"cap_add", "cap_drop", "expose", "external_links", "security_opt", "device_cgroup_rules", "profiles"} or item not in base]
    return new


def _safe_text(value):
    value = str(value)
    if "${" in value or UNKNOWN in value:
        return UNKNOWN
    value = re.sub(r"(?<=://)[^/@\s]+@", "[redacted]@", value)
    if "://" in value:
        value = re.sub(r"[?#].*$", "[redacted]", value)
    return value


# Non-structural values remain private even when a future Compose field is added.
_STRUCTURAL = set("image profiles restart user group_add privileged read_only init tty stdin_open network_mode pid ipc uts cgroup cgroup_parent cap_add cap_drop security_opt sysctls expose ports volumes networks depends_on deploy resources limits reservations cpus cpu_count cpu_percent cpu_shares cpu_period cpu_quota cpuset mem_limit mem_reservation mem_swappiness memswap_limit pids_limit ulimits oom_kill_disable oom_score_adj devices device_cgroup_rules device_requests driver count capabilities options type source target published host_ip protocol mode read_only bind volume tmpfs size propagation nocopy consistency condition required restart aliases ipv4_address ipv6_address link_local_ips priority gw_priority external name replicas placement constraints preferences max_replicas_per_node restart_policy delay max_attempts window endpoint_mode update_config rollback_config parallelism order failure_action monitor max_failure_ratio soft hard duration interval timeout start_period start_interval retries disable configs secrets uid gid read_only hostname domainname isolation runtime scale stop_grace_period stop_signal pull_policy platform internal attachable enable_ipv6 ipam subnet gateway ip_range aux_addresses driver_opts host_gateway dns dns_opt dns_search extra_hosts links external_links mac_address working_dir container_name healthcheck logging credential_spec blkio_config weight weight_device device_read_bps device_write_bps device_read_iops device_write_iops rate path models use_api_socket post_start pre_stop label_file env_file build dockerfile context pull no_cache shm_size cache_from cache_to ssh network entitlements ulimits detach_keys attach init".split())
_SECRET_NAME = re.compile(r"(?i)(password|passwd|token|secret|credential|private.?key|api.?key|auth)")
_PRIVATE = {"environment", "labels", "annotations", "command", "entrypoint", "test", "args", "dockerfile_inline", "content", "value", "credentials", "password", "token"}


def _hide_sensitive(value, secrets, issue, private=False, key=""):
    private = private or key in _PRIVATE
    if isinstance(value, dict):
        return {name: _hide_sensitive(child, secrets, issue, private, name) for name, child in value.items()}
    if isinstance(value, list):
        return [_hide_sensitive(child, secrets, issue, private, key) for child in value]
    if not private and isinstance(value, str) and any(secret in value for secret in secrets):
        issue("sensitive_interpolation", "A structural field contains a sensitive supplied value; supply a nonsecret structural value.")
        return UNKNOWN
    return value


def _sanitize(value, key=""):
    if key in _PRIVATE:
        return {str(k): REDACTED for k in value} if isinstance(value, dict) else REDACTED
    if key.startswith("x-"):
        return REDACTED
    if isinstance(value, dict):
        return {str(k): _sanitize(v, str(k)) if str(k) in _STRUCTURAL or isinstance(v, (dict, list)) else REDACTED for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize(child, key) for child in value] if key in _STRUCTURAL else REDACTED
    if key not in _STRUCTURAL:
        return REDACTED
    return _safe_text(value) if isinstance(value, str) else value


def discover(bundle_root: Path, files: list[str], profiles: list[str] | None = None) -> dict:
    """Normalize selected files in explicit order; [] discovers the default pair.

    Issues never contain source values. ``complete`` means image discovery has
    no blockers, not that deployment inputs were resolved or proven safe.
    Disabled profiles are omitted. Runtime gaps remain as review notes.
    """
    root = Path(bundle_root).resolve()
    issues, findings, services, images, sources = [], [], [], [], []
    current_source, current_service = None, None
    read_sizes = {}

    def read_input(name):
        text = _read(root, name)
        read_sizes[name] = len(text.encode("utf-8"))
        if len(read_sizes) > MAX_FILES or sum(read_sizes.values()) > MAX_TOTAL:
            raise ComposeInputError("Compose inputs exceed aggregate read limits.")
        return text

    def issue(code, message, blocking=None):
        # Runtime configuration is review evidence, not a prerequisite for an
        # image assessment. Unresolved image/platform/profile fields are checked
        # separately after interpolation and merging.
        if blocking is None:
            blocking = code not in {
                "required_variable", "unresolved_variable", "interpolation",
                "sensitive_interpolation", "unsupported_dotenv",
                "missing_env_file", "unsupported_env_file", "unresolved_environment",
                "missing_configs", "missing_secrets", "external_configs", "external_secrets",
                "external_bind_input", "unresolved_bind_input",
                "missing_networks", "missing_volumes", "external_networks", "external_volumes",
                "missing_build_input", "unsupported_build_context", "missing_dependency",
            }
        record = {"code": code, "message": message, "service": current_service, "source": current_source, "blocking": blocking}
        if record not in issues:
            issues.append(record)

    def finish():
        return {"services": services, "images": images, "issues": issues, "findings": findings, "complete": not any(i["blocking"] for i in issues), "sources": sources}

    try:
        files = [_relative(name) for name in files]
        if not files:
            candidates = [p for p in root.rglob("*") if p.is_file() and p.name in ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml")]
            if len(candidates) != 1:
                issue("compose_selection", "Select the Compose files explicitly in override order; no unique primary file was found.")
                return finish()
            primary = candidates[0]
            files = [primary.relative_to(root).as_posix()]
            overrides = [primary.with_name(name) for name in ("compose.override.yaml", "compose.override.yml", "docker-compose.override.yaml", "docker-compose.override.yml") if primary.with_name(name).is_file()]
            if len(overrides) > 1:
                issue("compose_selection", "Multiple default overrides exist; select files explicitly in order."); return finish()
            files += [p.relative_to(root).as_posix() for p in overrides]
        if len(files) > 50 or len(set(files)) != len(files):
            issue("compose_selection", "Select at most 50 distinct Compose files in order."); return finish()
        base = PurePosixPath(files[0]).parent
        def local(name):
            return _relative((base / str(name)).as_posix())
        env = {}
        dotenv = local(".env")
        if _inside(root, dotenv).exists():
            current_source = dotenv
            env = _dotenv(read_input(dotenv), {}, issue)
            env = {key: value for key, value in env.items() if value is not None}
            if "COMPOSE_FILE" in env:
                issue("unsupported_compose_file", "Bundle .env COMPOSE_FILE is not applied; select Compose files explicitly in order.")
        model, provenance = {}, {}
        for filename in files:
            current_source, current_service = filename, None
            document = _yaml(read_input(filename))
            if not isinstance(document, dict) or not isinstance(document.get("services", {}), dict):
                issue("compose_schema", "Selected file must contain a services mapping."); continue
            for key in ("include",):
                if key in document:
                    issue("unsupported_feature", "Compose include requires a supplied, explicitly flattened Compose file.")
            # Attribute interpolation notes to the consuming service, including
            # expanded YAML anchors, without retaining any source values.
            service_documents = document.get("services", {})
            document = _interpolate({key: value for key, value in document.items() if key != "services"}, env, issue)
            document["services"] = {}
            for service_name, service_document in service_documents.items():
                current_service = service_name
                document["services"][service_name] = _interpolate(service_document, env, issue)
            current_service = None
            for service_config in document.get("services", {}).values():
                if not isinstance(service_config, dict):
                    continue
                for field in ("env_file", "dns", "dns_search", "tmpfs"):
                    if isinstance(service_config.get(field), str):
                        service_config[field] = [service_config[field]]
                for field in ("depends_on", "networks"):
                    if isinstance(service_config.get(field), list):
                        service_config[field] = {name: {"condition": "service_started", "required": True} if field == "depends_on" else {} for name in service_config[field]}
            model = _merge(model, document)
            sources.append(filename)
            for name in document.get("services", {}):
                provenance.setdefault(name, []).append(filename)
        for name, config in model.get("services", {}).items():
            current_service, current_source = name, provenance[name][-1]
            if not isinstance(config, dict):
                issue("compose_schema", "Service definition must be a mapping."); continue
            active_profiles = config.get("profiles", [])
            if not isinstance(active_profiles, list):
                issue("compose_schema", "Service profiles must be a list."); continue
            if UNKNOWN in str(active_profiles):
                issue("unresolved_profiles", "Resolve service profiles before scanning so CATS can determine which images are included."); continue
            if active_profiles and "*" not in (profiles or []) and not set(active_profiles).intersection(profiles or []):
                continue
            for key in ("extends", "provider", "develop", "label_file", "models", "post_start", "pre_stop"):
                if key in config:
                    issue("unsupported_feature", "Service uses a feature requiring a supplied, explicitly flattened Compose configuration.", blocking=key in {"extends", "provider", "models"})
            valid_shape = True
            for field in ("ports", "volumes", "configs", "secrets", "expose", "cap_add", "cap_drop", "security_opt"):
                if field in config and config[field] is not None and not isinstance(config[field], list):
                    issue("compose_schema", "Service sequence field has an invalid type; provide a Compose list.", blocking=False)
                    valid_shape = False
            for field in ("environment", "depends_on", "networks"):
                if field in config and config[field] is not None and not isinstance(config[field], (list, dict)):
                    issue("compose_schema", "Service mapping or sequence field has an invalid type.", blocking=False)
                    valid_shape = False
            for field in ("deploy", "healthcheck", "logging", "ulimits", "blkio_config"):
                if field in config and config[field] is not None and not isinstance(config[field], dict):
                    issue("compose_schema", "Service configuration field requires a mapping.", blocking=False)
                    config[field] = {"unresolved": UNKNOWN}
            for field in ("privileged", "read_only", "init", "tty", "stdin_open", "oom_kill_disable"):
                if field in config and config[field] is not None and not isinstance(config[field], bool) and config[field] != UNKNOWN:
                    issue("compose_schema", "Service boolean field must be an explicit true or false value.", blocking=False)
            if not valid_shape:
                # Image discovery remains possible without interpreting malformed resources.
                config = {key: value for key, value in config.items() if key not in {"ports", "volumes", "configs", "secrets", "expose", "cap_add", "cap_drop", "security_opt", "environment", "depends_on", "networks"}}
            runtime_env = {}
            env_files = config.get("env_file", [])
            if not isinstance(env_files, list):
                env_files = [env_files]
            for entry in env_files:
                filename = entry.get("path") if isinstance(entry, dict) else entry
                required = entry.get("required", True) if isinstance(entry, dict) else True
                try:
                    env_path = local(filename)
                    if not _inside(root, env_path).exists() and required is False:
                        continue
                    fmt = entry.get("format") if isinstance(entry, dict) else None
                    if fmt not in (None, "raw"):
                        issue("unsupported_env_file", "env_file format must be default or raw."); continue
                    runtime_env.update(_dotenv(read_input(env_path), env, issue, raw=fmt == "raw"))
                except ComposeInputError:
                    issue("missing_env_file", "Service env_file must be supplied inside the bundle.")
            runtime_env.update(_mapping(config.get("environment")))
            for key, value in runtime_env.items():
                if value is None:
                    runtime_env[key] = env.get(key, UNKNOWN)
                    if key not in env:
                        issue("unresolved_environment", "A pass-through environment variable has no supplied bundle value.")
            config["environment"] = runtime_env
            for kind in ("configs", "secrets"):
                for entry in config.get(kind, []) or []:
                    ref = entry.get("source") if isinstance(entry, dict) else entry
                    definition = model.get(kind, {}).get(ref)
                    if not isinstance(definition, dict):
                        issue("missing_" + kind, "Referenced configuration or secret must have a supplied definition."); continue
                    if definition.get("external"):
                        issue("external_" + kind, "External configuration or secret availability cannot be verified from the bundle.")
                    if "file" in definition:
                        try:
                            read_input(local(definition["file"]))
                        except ComposeInputError:
                            issue("missing_" + kind, "Referenced configuration or secret file must be supplied inside the bundle.")
                    if "environment" in definition:
                        issue("external_" + kind, "Host environment sourced configuration or secret requires an explicit bundle input.")
            sensitive_values = {str(value) for key, value in {**env, **runtime_env}.items()
                                if _SECRET_NAME.search(key) and value not in (None, "", UNKNOWN)}
            config = _hide_sensitive(config, sensitive_values, issue)
            image = config.get("image")
            if not isinstance(image, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/:@+\-]{0,999}", image) or "://" in image or "@" in image and not re.search(r"@sha256:[a-fA-F0-9]{64}$", image):
                image = None
                issue("unresolved_image", "Service requires a valid, explicitly resolved image reference to scan. Supply image variables in the bundle .env file or declare the image directly.")
            if "build" in config:
                issue("image_and_build" if image else "build_only", "Only the explicit image is scanned; local build output is not assessed." if image else "Build-only service cannot be scanned; supply a prebuilt image reference.", blocking=not bool(image))
                build = config["build"]
                if isinstance(build, dict) and build.get("additional_contexts"):
                    issue("unsupported_build_context", "Additional build contexts require a separately built and scanned image.")
                context = build.get("context", ".") if isinstance(build, dict) else build
                try:
                    context_path = _inside(root, local(context))
                    if not context_path.is_dir():
                        raise ComposeInputError("Missing build context.")
                    if not isinstance(build, dict) or "dockerfile_inline" not in build:
                        dockerfile = build.get("dockerfile", "Dockerfile") if isinstance(build, dict) else "Dockerfile"
                        read_input(local(str(PurePosixPath(str(context)) / str(dockerfile))))
                except ComposeInputError:
                    issue("missing_build_input", "Build context and Dockerfile must be supplied inside the bundle; remote or host paths are unsupported.")
            if config.get("platform"):
                issue("unsupported_platform", "Explicit service platform cannot be honored by this image scanner; provide a matching platform-aware scan or remove the constraint after verifying the image platform.")
            if image and not config.get("platform") and image not in images:
                images.append(image)
            sanitized = _sanitize(config)
            sanitized["image"] = image
            sanitized["scan_eligible"] = bool(image) and not bool(config.get("platform"))
            for resource in ("networks", "volumes", "configs", "secrets"):
                definitions = model.get(resource, {})
                if isinstance(definitions, dict):
                    sanitized[resource + "_definitions"] = {key: _sanitize(_hide_sensitive(value or {}, sensitive_values, issue), resource) for key, value in definitions.items()}
            sanitized["ports"] = [_sanitize(_port(p), "ports") for p in config.get("ports", []) or []]
            sanitized["volumes"] = [_sanitize(_mount(v), "volumes") for v in config.get("volumes", []) or []]
            sanitized["environment"] = {key: REDACTED for key in runtime_env}
            service_issues = [i for i in issues if i["blocking"] and (i["service"] == name or i["service"] is None)]
            services.append({"name": name, "image": image, "configuration": sanitized, "source_files": provenance[name], "status": "incomplete" if service_issues else "resolved"})
            checks = [(config.get("privileged") is True, "COMPOSE-PRIVILEGED", "High", "Privileged container", "Disable privileged mode and grant only required capabilities."), (config.get("network_mode") == "host", "COMPOSE-HOST-NETWORK", "Medium", "Host network namespace", "Use an isolated Compose network."), (config.get("pid") == "host", "COMPOSE-HOST-PID", "High", "Host process namespace", "Use the container's own process namespace.")]
            mounts = [_mount(value) for value in config.get("volumes", []) or []]
            for mount in mounts:
                if mount.get("type") == "bind":
                    source = mount.get("source")
                    if mount.get("unresolved") or source == UNKNOWN or mount.get("target") == UNKNOWN:
                        issue("unresolved_bind_input", "Bind mount syntax or path is unresolved; supply an explicit supported local bind mapping and its bundle input.")
                    if source and source != UNKNOWN:
                        try:
                            if not _inside(root, local(source)).exists():
                                raise ComposeInputError("Missing bind input.")
                        except ComposeInputError:
                            issue("external_bind_input", "Bind mount input is unavailable inside the bundle; supply local configuration files or verify the host prerequisite separately.")
            for kind in ("networks", "volumes"):
                refs = config.get("networks", {}) or {} if kind == "networks" else [m.get("source") for m in mounts if m.get("type") == "volume" and m.get("source")]
                definitions = model.get(kind, {}) or {}
                if not isinstance(definitions, dict):
                    issue("compose_schema", f"Top-level {kind} must be a mapping.", blocking=False)
                    continue
                for ref in refs:
                    definition = definitions.get(ref)
                    # A null definition declares a resource with Compose defaults.
                    if ref not in definitions and not (kind == "networks" and ref == "default"):
                        issue("missing_" + kind, "Named network or volume requires a top-level definition.")
                    elif definition is not None and not isinstance(definition, dict):
                        issue("compose_schema", f"Named {kind} definition must be empty or a mapping.", blocking=False)
                    if isinstance(definition, dict) and definition.get("external"):
                        issue("external_" + kind, "External network or volume availability cannot be verified from the bundle.")
            user = config.get("user")
            user_root = str(user).split(":", 1)[0] in ("0", "root") if user is not None else False
            caps = config.get("cap_add", []) or []
            powerful_caps = any(str(cap).upper() in {"ALL", "SYS_ADMIN", "SYS_PTRACE", "DAC_READ_SEARCH", "NET_ADMIN", "SYS_MODULE", "SYS_RAWIO"} for cap in caps)
            options = config.get("security_opt", []) or []
            unconfined = any(str(option).replace("=", ":") in {"seccomp:unconfined", "apparmor:unconfined", "label:disable"} for option in options)
            ports = [_port(value) for value in config.get("ports", []) or []]
            public_ports = any(p.get("published") is not None and p.get("host_ip") in (None, "", "0.0.0.0", "::") and UNKNOWN not in str(p) for p in ports)
            resource_config = config.get("deploy", {}) or {}
            resources = resource_config.get("resources", {}) if isinstance(resource_config, dict) else {}
            limits = resources.get("limits", {}) if isinstance(resources, dict) else {}
            missing_limits = not config.get("mem_limit") and not config.get("cpus") and not config.get("cpu_quota") and not limits and UNKNOWN not in str(resources) and UNKNOWN not in str(resource_config)
            checks += [
                (any(m.get("source") in {"/var/run/docker.sock", "/run/docker.sock"} or m.get("target") in {"/var/run/docker.sock", "/run/docker.sock"} for m in mounts), "COMPOSE-DOCKER-SOCKET", "Critical", "Docker socket mounted", "Remove the Docker socket mount; use a restricted API proxy only when required."),
                (powerful_caps, "COMPOSE-CAPABILITIES", "High", "Powerful Linux capabilities added", "Drop unnecessary capabilities and grant only those required."),
                (user_root, "COMPOSE-ROOT-USER", "Medium", "Explicit root container user", "Configure a non-root user compatible with the image."),
                (unconfined, "COMPOSE-UNCONFINED", "High", "Container security confinement disabled", "Enable an appropriate seccomp, AppArmor or SELinux profile."),
                (public_ports, "COMPOSE-PUBLISHED-PORTS", "Medium", "Ports published on all host interfaces", "Bind published ports to a required host interface and restrict network access."),
                (missing_limits, "COMPOSE-NO-RESOURCE-LIMITS", "Low", "No CPU or memory limits declared", "Declare appropriate CPU and memory limits for this workload.")]
            if any(i["blocking"] and i["service"] == name for i in issues):
                services[-1]["status"] = "incomplete"
            for enabled, code, severity, title, remedy in checks:
                if enabled:
                    findings.append({"type": "Configuration", "finding": code, "severity": severity, "scanner": "CATS Compose", "framework": "Docker Compose", "target": name, "title": title, "description": "Explicit Compose configuration enables this setting; runtime state was not inspected.", "remediation": remedy, "evidence": {"service": name, "source_files": provenance[name]}})
        selected_names = {s["name"] for s in services}
        for service in services:
            current_service = service["name"]
            current_source = service["source_files"][-1]
            dependencies = model["services"][current_service].get("depends_on", {}) or {}
            if not isinstance(dependencies, (dict, list)):
                continue
            for dependency in dependencies:
                options = dependencies.get(dependency, {}) if isinstance(dependencies, dict) else {}
                if dependency not in selected_names and (not isinstance(options, dict) or options.get("required", True)):
                    issue("missing_dependency", "Required dependency is missing or excluded by selected profiles.")
        if any(i["blocking"] and i["service"] is None for i in issues):
            for service in services:
                service["status"] = "incomplete"
        if not services:
            issue("no_active_services", "No active Compose services were discovered; check selected files and profiles.")
    except ComposeInputError as exc:
        issue("invalid_input", str(exc))
    except (TypeError, ValueError, AttributeError, KeyError, OSError, RecursionError):
        issue("compose_schema", "Compose structure is invalid or unsupported; validate field types and supply explicit local inputs.")
    return finish()
