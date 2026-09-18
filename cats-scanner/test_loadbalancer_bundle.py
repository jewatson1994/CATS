"""Small dependency-free archive integrity regression tests (plus PyYAML)."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("bundle", Path(__file__).with_name("build-loadbalancer-bundle.py"))
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)


class ArchiveIntegrityTests(unittest.TestCase):
    def make_archive(self, path, *, mutate_layer=False, wrong_tag=False):
        layer = b"example uncompressed layer"
        config = json.dumps({"architecture": "amd64", "os": "linux", "rootfs": {
            "diff_ids": ["sha256:" + hashlib.sha256(layer).hexdigest()]}}).encode()
        record = [{"Config": "config.json", "RepoTags": ["wrong" if wrong_tag else "example:v1"],
                   "Layers": ["layer.tar"]}]
        files = {"manifest.json": json.dumps(record).encode(), "config.json": config,
                 "layer.tar": b"tampered" if mutate_layer else layer}
        with tarfile.open(path, "w") as archive:
            for name, data in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return hashlib.sha256(config).hexdigest()

    def test_verified_offline_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.tar"
            digest = self.make_archive(path)
            bundle.verify_archive(path, "example:v1", digest)

    def test_mutated_layer_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.tar"
            digest = self.make_archive(path, mutate_layer=True)
            with self.assertRaisesRegex(ValueError, "layer digest mismatch"):
                bundle.verify_archive(path, "example:v1", digest)

    def test_wrong_config_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.tar"
            self.make_archive(path)
            with self.assertRaisesRegex(ValueError, "config digest mismatch"):
                bundle.verify_archive(path, "example:v1", "0" * 64)

    def test_wrong_tag_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.tar"
            digest = self.make_archive(path, wrong_tag=True)
            with self.assertRaisesRegex(ValueError, "Unexpected image tags"):
                bundle.verify_archive(path, "example:v1", digest)


if __name__ == "__main__":
    unittest.main()
