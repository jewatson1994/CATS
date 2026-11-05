"""Build-time checks for the static executables mounted into isolated actions."""
import json
from pathlib import Path
import struct
import subprocess
import sys


def static_elf(path):
    with Path(path).open("rb") as stream:
        header = stream.read(64)
        if header[:4] != b"\x7fELF" or header[4:6] != b"\x02\x01":
            raise ValueError(f"Expected a little-endian 64-bit ELF executable: {path}")
        offset = struct.unpack_from("<Q", header, 32)[0]
        entry_size, count = struct.unpack_from("<HH", header, 54)
        for index in range(count):
            stream.seek(offset + index * entry_size)
            if struct.unpack("<I", stream.read(4))[0] == 3:  # PT_INTERP
                raise ValueError(f"Isolated executable requires a dynamic loader: {path}")


def main():
    expected_helm, expected_kubectl, expected_compose = sys.argv[1:]
    commands = {
        "helm": ["/usr/local/bin/helm", "version", "--short"],
        "kubectl": ["/usr/local/bin/kubectl", "version", "--client", "-o", "json"],
        "compose": ["/usr/local/bin/docker-compose", "version", "--short"],
    }
    versions = {}
    for name, command in commands.items():
        static_elf(command[0])
        versions[name] = subprocess.check_output(command, text=True).strip()
    kubectl = json.loads(versions["kubectl"])
    versions["kubectl"] = kubectl["clientVersion"]["gitVersion"]
    versions["kustomize"] = kubectl["kustomizeVersion"]
    expected = {"helm": expected_helm, "kubectl": expected_kubectl, "compose": expected_compose}
    for name, pin in expected.items():
        if versions[name].lstrip("v").split("+", 1)[0] != pin:
            raise ValueError(f"{name} version does not match {pin}; rebuild the pinned scanner base")
    versions["bubblewrap"] = subprocess.check_output(["/usr/bin/bwrap", "--version"], text=True).strip()
    for name in ("syft", "grype", "trivy", "dockle"):
        executable = "/usr/local/bin/" + name
        static_elf(executable)
        versions[name] = subprocess.check_output([executable, "version" if name in {"syft", "grype"} else "--version"], text=True).strip()
    versions["skopeo"] = subprocess.check_output(["skopeo", "--version"], text=True).strip()
    destination = Path("/opt/discovery/tool-versions.json")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(versions, sort_keys=True) + "\n")
    print(json.dumps(versions, sort_keys=True))


if __name__ == "__main__":
    main()
