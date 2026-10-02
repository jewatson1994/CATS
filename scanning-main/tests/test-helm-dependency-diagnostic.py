import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("diagnostic", Path(__file__).parents[1] / "scripts" / "helm-dependency-diagnostic.py")
diagnostic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diagnostic)


class DependencyDiagnosticTests(unittest.TestCase):
    def test_missing_exact_dependency(self):
        message = diagnostic.summarize('Error: failed to download oci://oci.trueforge.org/truecharts/common:29.3.4: not found')
        self.assertIn("chart/version was not found", message)
        self.assertIn("common:29.3.4", message)

    def test_http_rejection(self):
        self.assertIn("HTTP 403", diagnostic.summarize("failed to fetch https://helm.elastic.co/index.yaml: 403"))

    def test_credentials_and_response_body_are_not_echoed(self):
        message = diagnostic.summarize('403 https://user:password@example.test/chart?token=secret#private Authorization: Bearer sensitive')
        self.assertIn("https://example.test/chart", message)
        for secret in ("user", "password", "token", "secret", "private", "sensitive", "Authorization"):
            self.assertNotIn(secret, message)

    def test_unknown_error_is_safe(self):
        self.assertNotIn("password", diagnostic.summarize("arbitrary password output"))

    def test_network_gate(self):
        self.assertIn("HELM_ALLOW_NETWORK=false", diagnostic.summarize("HELM_ALLOW_NETWORK=false"))


if __name__ == "__main__":
    unittest.main()
