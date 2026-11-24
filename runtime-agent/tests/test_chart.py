"""Render the real chart with Helm and verify the objects CATS installs."""
import base64
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "helm" / "cats-runtime"
META = yaml.safe_load((CHART / "Chart.yaml").read_text())
PORTAL = "https://cats.example.test"
KEY = "cats-link-example-test-key"


def helm(*args, check=True, cwd=None):
    result = subprocess.run(["helm", *map(str, args)], capture_output=True, text=True, cwd=cwd)
    if check and result.returncode:
        raise AssertionError(result.stderr)
    return result


def render(*args, chart=CHART, cwd=None):
    output = helm("template", "cluster-a", chart, "-n", "runtime", "--set-string", f"catsUrl={PORTAL}", *args, cwd=cwd)
    return {obj["kind"]: obj for obj in yaml.safe_load_all(output.stdout) if obj}


def pod(objects):
    return objects["Deployment"]["spec"]["template"]["spec"]


class RuntimeChartTest(unittest.TestCase):
    def test_package_and_install_with_only_url_and_key(self):
        with tempfile.TemporaryDirectory() as directory:
            helm("lint", CHART, "--strict", "--set-string", f"catsUrl={PORTAL}", "--set-string", f"linkingKey={KEY}")
            helm("package", CHART, "--destination", directory)
            archive = Path(directory) / f"cats-runtime-{META['version']}.tgz"
            self.assertTrue(archive.is_file())
            key_file = Path(directory) / "linking-key"
            key_file.write_text(KEY + "\n", encoding="utf-8")
            objects = render("--set-file", "linkingKey=linking-key", chart=archive, cwd=directory)
        secret = objects["Secret"]
        self.assertEqual(secret["metadata"]["namespace"], "runtime")
        self.assertEqual(base64.b64decode(secret["data"]["linking-key"]).decode(), KEY)
        deployment = objects["Deployment"]
        self.assertNotIn(KEY, str(deployment))
        self.assertNotIn(secret["data"]["linking-key"], str(deployment))
        self.assertEqual(deployment["spec"]["strategy"]["type"], "Recreate")
        self.assertEqual(deployment["spec"]["replicas"], 1)
        spec = pod(objects)
        self.assertEqual(spec["serviceAccountName"], objects["ServiceAccount"]["metadata"]["name"])
        self.assertEqual(objects["ClusterRole"]["rules"], [
            {"apiGroups": [""], "resources": ["pods", "namespaces"], "verbs": ["list", "watch"]},
            {"apiGroups": ["apps"], "resources": ["deployments", "statefulsets", "daemonsets", "replicasets"],
             "verbs": ["list", "watch"]},
            {"apiGroups": ["batch"], "resources": ["jobs", "cronjobs"], "verbs": ["list", "watch"]},
        ])
        binding = objects["ClusterRoleBinding"]
        self.assertEqual(binding["roleRef"]["name"], objects["ClusterRole"]["metadata"]["name"])
        self.assertEqual(binding["subjects"], [{"kind":"ServiceAccount", "name":spec["serviceAccountName"], "namespace":"runtime"}])
        container = spec["containers"][0]
        self.assertEqual(container["image"], "ghcr.io/jewatson1994/cats-runtime:" + META["appVersion"])
        self.assertEqual(container["args"], ["run","--source","kubernetes","--state-dir","/var/lib/cats-runtime/state"])
        env = {entry["name"]: entry["value"] for entry in container["env"]}
        self.assertEqual(env, {"CATS_URL":PORTAL, "CATS_AGENT_NAME":"cluster-a", "CATS_LINKING_KEY_FILE":"/run/cats-link/linking-key"})
        self.assertTrue(spec["securityContext"]["runAsNonRoot"])
        self.assertEqual(spec["securityContext"]["seccompProfile"]["type"], "RuntimeDefault")
        self.assertTrue(container["securityContext"]["readOnlyRootFilesystem"])
        self.assertFalse(container["securityContext"]["allowPrivilegeEscalation"])
        self.assertEqual(container["securityContext"]["capabilities"]["drop"], ["ALL"])
        self.assertIn("agent_id", container["readinessProbe"]["exec"]["command"][-1])
        volumes = {v["name"]: v for v in spec["volumes"]}
        self.assertEqual(volumes["link"]["secret"]["secretName"], secret["metadata"]["name"])
        self.assertEqual(volumes["link"]["secret"]["defaultMode"], 0o440)
        pvc = objects["PersistentVolumeClaim"]
        self.assertEqual(volumes["state"]["persistentVolumeClaim"]["claimName"], pvc["metadata"]["name"])
        self.assertEqual(pvc["metadata"]["annotations"]["helm.sh/resource-policy"], "keep")

    def test_external_secrets_offline_registry_and_existing_volume(self):
        digest = "sha256:" + "e" * 64
        overrides = [
            "linkingKeySecret=my-link-secret", "caSecret=custom-ca", "agentName=Staging",
            "image.repository=registry.internal/security/runtime", "image.tag=mirror-v1",
            "imagePullSecrets[0].name=mirror-pull", "persistence.existingClaim=existing-state",
        ]
        flags = [arg for setting in overrides for arg in ("--set-string", setting)]
        objects = render(*flags)
        self.assertNotIn("Secret", objects)
        self.assertNotIn("PersistentVolumeClaim", objects)
        spec = pod(objects)
        self.assertEqual(spec["imagePullSecrets"], [{"name":"mirror-pull"}])
        volumes = {v["name"]:v for v in spec["volumes"]}
        self.assertEqual(volumes["state"]["persistentVolumeClaim"]["claimName"], "existing-state")
        for name, secret, key in [("link","my-link-secret","linking-key"), ("ca","custom-ca","ca.crt")]:
            self.assertEqual(volumes[name]["secret"]["secretName"], secret)
            self.assertEqual(volumes[name]["secret"]["items"], [{"key":key, "path":key}])
        container = spec["containers"][0]
        self.assertEqual(container["image"], "registry.internal/security/runtime:mirror-v1")
        self.assertIn({"name":"CATS_CA_FILE","value":"/run/cats-ca/ca.crt"}, container["env"])
        self.assertEqual(pod(render(*flags, "--set-string", f"image.digest={digest}"))["containers"][0]["image"],
                         "registry.internal/security/runtime@" + digest)

    def test_existing_enrollment_does_not_need_bootstrap_material(self):
        for flags, expected in [(["--is-upgrade"], "cluster-a-state"),
                                (["--set-string", "persistence.existingClaim=restored-state"], "restored-state")]:
            objects = render(*flags)
            self.assertNotIn("Secret", objects)
            spec = pod(objects)
            self.assertEqual(spec["volumes"], [{"name":"state", "persistentVolumeClaim":{"claimName":expected}}])
            self.assertNotIn("CATS_LINKING_KEY_FILE", str(spec["containers"][0]["env"]))

    def test_bare_authority_uses_verified_https(self):
        for endpoint in ["10.2.3.4:8443", "cats.internal", "[fd00::1]:443"]:
            with self.subTest(endpoint=endpoint):
                output = helm("template", "demo", CHART, "--set-string", f"catsUrl={endpoint}",
                              "--set-string", "linkingKey=key")
                deployment = next(doc for doc in yaml.safe_load_all(output.stdout) if doc["kind"] == "Deployment")
                env = deployment["spec"]["template"]["spec"]["containers"][0]["env"]
                self.assertIn({"name": "CATS_URL", "value": "https://" + endpoint}, env)

    def test_reject_invalid_install_configuration(self):
        for values, message in [
            ([f"catsUrl={PORTAL}"], "Set linkingKey or linkingKeySecret"),
            (["linkingKey=key"], "Set catsUrl"),
            (["catsUrl=http://cats","linkingKey=key"], "HTTPS portal URL"),
            (["catsUrl=cats.internal/path","linkingKey=key"], "HTTPS portal URL"),
            (["catsUrl=https://user:pw@cats","linkingKey=key"], "HTTPS portal URL"),
            ([f"catsUrl={PORTAL}", "linkingKey=key", "linkingKeySecret=other"], "Choose either"),
            ([f"catsUrl={PORTAL}", "linkingKey=key", "image.digest=latest"], "sha256 manifest digest"),
        ]:
            flags = [arg for value in values for arg in ("--set-string", value)]
            result = helm("template","demo",CHART,*flags,check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(message, result.stderr)


if __name__ == "__main__":
    unittest.main()
