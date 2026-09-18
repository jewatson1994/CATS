"""Integrity regressions for the pinned offline ingress bundle builder."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest


spec = importlib.util.spec_from_file_location("ingress_bundle", Path(__file__).with_name("build-ingress-bundle.py"))
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)


class IngressArchiveIntegrityTests(unittest.TestCase):
    def make_archive(self, path, *, mutate_layer=False, architecture="amd64"):
        layer = b"example ingress image layer"
        config = json.dumps({
            "architecture": architecture, "os": "linux",
            "rootfs": {"diff_ids": ["sha256:" + hashlib.sha256(layer).hexdigest()]},
        }).encode()
        record = [{"Config": "config.json", "RepoTags": ["example:v1"], "Layers": ["layer.tar"]}]
        files = {
            "manifest.json": json.dumps(record).encode(), "config.json": config,
            "layer.tar": b"tampered" if mutate_layer else layer,
        }
        with tarfile.open(path, "w") as archive:
            for name, data in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return hashlib.sha256(config).hexdigest()

    def test_inventory_is_fully_pinned(self):
        self.assertEqual(bundle.VERSION, "1.15.1")
        self.assertEqual(bundle.CERTGEN_VERSION, "1.6.9")
        self.assertEqual(len(bundle.SOURCE_MANIFEST_SHA256), 64)
        for item in bundle.IMAGES.values():
            self.assertEqual(len(item["digest"]), 64)
            self.assertEqual(len(item["config"]), 64)

    def test_verified_archive_and_tamper_detection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.tar"
            config = self.make_archive(path)
            bundle.verify_archive(path, "example:v1", config)

            path = Path(directory) / "tampered.tar"
            config = self.make_archive(path, mutate_layer=True)
            with self.assertRaisesRegex(ValueError, "layer digest mismatch"):
                bundle.verify_archive(path, "example:v1", config)

    def test_non_amd64_archive_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.tar"
            config = self.make_archive(path, architecture="arm64")
            with self.assertRaisesRegex(ValueError, "linux/amd64"):
                bundle.verify_archive(path, "example:v1", config)


if __name__ == "__main__":
    unittest.main()
