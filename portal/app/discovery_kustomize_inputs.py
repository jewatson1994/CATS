"""Conservative local Kustomize input closure; None requests a full-tree snapshot."""
from pathlib import Path
import os
import yaml

_MARKERS = ("kustomization.yaml", "kustomization.yml", "Kustomization")
_PASSIVE = {"apiVersion", "kind", "metadata", "namePrefix", "nameSuffix", "namespace",
            "commonLabels", "commonAnnotations", "labels", "annotations", "images",
            "replicas", "vars", "generatorOptions", "buildMetadata", "sortOptions"}
_DEPENDENCIES = {"resources", "bases", "components", "patches", "patchesStrategicMerge",
                 "patchesJson6902", "configMapGenerator", "secretGenerator", "configurations", "crds"}


class _Unsupported(ValueError):
    pass


class _Loader(yaml.SafeLoader):
    pass


def _mapping(loader, node):
    result = {}
    for key, value in node.value:
        key = loader.construct_object(key, deep=True)
        if not isinstance(key, str) or key in result:
            raise _Unsupported("ambiguous mapping")
        result[key] = loader.construct_object(value, deep=True)
    return result


_Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def collect_inputs(root: Path, base: Path) -> set[Path] | None:
    """Return absolute files beneath base, or None for unsupported/unsafe inputs.

    Supports local resources/bases/components, file and inline patches, generator
    files/envs, configurations and CRDs. Helm, plugins, replacements and other
    unknown fields deliberately fall back. Limits: 128 directories, 64 nesting
    levels, 4096 files, and 1 MiB per kustomization. Never follows symlinks.
    """
    selected: set[Path] = set()
    active: set[Path] = set()
    visited: set[Path] = set()
    base = Path(os.path.abspath(base))

    def checked(path):
        path = Path(os.path.abspath(path))
        if not path.is_relative_to(base):
            raise _Unsupported("outside base")
        # Include ancestors of base: a symlinked base is equally unsafe.
        for part in (path, *path.parents):
            if part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction()):
                raise _Unsupported("linked input")
        if not path.exists():
            raise _Unsupported("missing input")
        return path

    def local(directory, value):
        if not isinstance(value, str) or not value or any(c in value for c in (":", "?", "#", "\\", "\n", "\r", "\x00")) or Path(value).is_absolute():
            raise _Unsupported("non-local input")
        # Inspect each component before normalization can erase a symlink.
        path = directory
        for part in Path(value).parts:
            path = checked(path / part)
        return path

    def add(path):
        path = checked(path)
        if not path.is_file():
            raise _Unsupported("expected file")
        selected.add(path)
        if len(selected) > 4096:
            raise _Unsupported("file limit")

    def rows(data, key):
        value = data.get(key, [])
        if not isinstance(value, list):
            raise _Unsupported("expected list")
        return value

    def visit(directory):
        directory = checked(directory)
        if directory in active or len(active) >= 64:
            raise _Unsupported("cycle or depth limit")
        if directory in visited:
            return
        if len(visited) + len(active) >= 128:
            raise _Unsupported("directory limit")
        active.add(directory)
        markers = [directory / name for name in _MARKERS if (directory / name).exists() or (directory / name).is_symlink()]
        if len(markers) != 1:
            raise _Unsupported("ambiguous kustomization")
        marker = checked(markers[0])
        add(marker)
        if marker.stat().st_size > 1024 * 1024:
            raise _Unsupported("document limit")
        data = yaml.load(marker.read_text(encoding="utf-8-sig"), Loader=_Loader)
        if not isinstance(data, dict) or set(data) - _PASSIVE - _DEPENDENCIES:
            raise _Unsupported("unsupported schema")
        for key in ("resources", "bases", "components"):
            for value in rows(data, key):
                path = local(directory, value)
                visit(path) if path.is_dir() else add(path)
        for key in ("configurations", "crds"):
            for value in rows(data, key):
                add(local(directory, value))
        for key in ("patches", "patchesJson6902", "patchesStrategicMerge"):
            for value in rows(data, key):
                if key == "patchesStrategicMerge":
                    if isinstance(value, dict):
                        continue  # Inline strategic merge object.
                    if isinstance(value, str) and "\n" in value:
                        continue  # Inline patch text.
                    add(local(directory, value))
                else:
                    if not isinstance(value, dict) or set(value) - {"path", "patch", "target", "options"} or ("path" in value) == ("patch" in value):
                        raise _Unsupported("unsupported patch")
                    if "path" in value:
                        add(local(directory, value["path"]))
                    elif not isinstance(value["patch"], str):
                        raise _Unsupported("unsupported inline patch")
        for key in ("configMapGenerator", "secretGenerator"):
            for value in rows(data, key):
                if not isinstance(value, dict) or set(value) - {"name", "namespace", "behavior", "type", "options", "literals", "files", "envs", "env"}:
                    raise _Unsupported("unsupported generator")
                for item in rows(value, "files"):
                    if not isinstance(item, str):
                        raise _Unsupported("unsupported generator file")
                    add(local(directory, item.split("=", 1)[-1]))
                for item in rows(value, "envs"):
                    add(local(directory, item))
                if "env" in value:
                    add(local(directory, value["env"]))
        active.remove(directory)
        visited.add(directory)

    try:
        visit(Path(root))
        return selected
    except (OSError, ValueError, TypeError, RecursionError, yaml.YAMLError):
        return None
