"""Deployment safety checks plus real Compose interpolation/merge contracts."""
import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch, Mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("guided_setup", ROOT / "scripts/setup-cats.py")
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)


class SetupTests(unittest.TestCase):
    def test_environment_round_trip_keeps_secrets_literal(self):
        values = {"DOLLARS": "$HOME ${INJECT} $$", "QUOTE": "back\\'quote", "END": "ends\\",
                  "HASH": "spaces # comments", "JSON": '{"x":"q"}'}
        self.assertEqual(setup.parse_env(setup.serialize_env(values)), values)
        self.assertEqual(setup.parse_env("X='literal$HOME' # comment\nY=ok # comment"),
                         {"X": "literal$HOME", "Y": "ok"})

    def test_ambiguous_existing_env_stops_without_executing_it(self):
        for text in ("X=${SECRET}", "X=$HOME", "X=a\nX=b", "$(touch /bad)", "X='unterminated"):
            with self.subTest(text=text), self.assertRaises(setup.SetupError):
                setup.parse_env(text)

    def test_existing_passwords_and_encryption_key_never_regenerated(self):
        values = {"POSTGRES_PASSWORD": "legacy-password", "CATS_CONFIG_ENCRYPTION_KEY": base64.urlsafe_b64encode(b"a" * 32).decode()}
        before = values.copy()
        with patch.object(setup, "ask", side_effect=AssertionError("Must not prompt to regenerate")):
            setup.required_secret(values, "POSTGRES_PASSWORD", "database")
            setup.required_secret(values, "CATS_CONFIG_ENCRYPTION_KEY", "key", fernet=True)
        self.assertEqual(values, before)

    def test_new_secrets_are_secure_and_fernet_formatted(self):
        values = {}
        with patch.object(setup, "ask", return_value=""):
            setup.required_secret(values, "POSTGRES_PASSWORD", "database")
            setup.required_secret(values, "CATS_CONFIG_ENCRYPTION_KEY", "key", fernet=True)
        self.assertGreaterEqual(len(values["POSTGRES_PASSWORD"]), 32)
        self.assertEqual(len(base64.urlsafe_b64decode(values["CATS_CONFIG_ENCRYPTION_KEY"])), 32)

    def test_fresh_setup_uses_host_certificate_and_scan_defaults(self):
        existing = {"CATS_IMAGE": "cats:test",
                    "CATS_PORTAL_HOSTNAME": "portal.example", "CATS_OCI_HOSTNAME": "registry.example"}
        for mode in ("main", "replica"):
            with self.subTest(mode=mode), \
                 patch.object(setup, "ask", side_effect=lambda label, default="", secret=False: default), \
                 patch.object(setup, "certificate", side_effect=lambda directory, name: directory) as certificate:
                values = setup.gather(mode, existing, {})
            self.assertEqual(values["CATS_PORTAL_CERT_DIR"], "/opt/cats/certs/portal")
            self.assertEqual(values["CATS_OCI_CERT_DIR"], "/opt/cats/certs/oci-proxy")
            self.assertEqual(values["CATS_IMAGE"], "cats:test")
            self.assertNotIn("CATS_REPLICA_IMAGE", values)
            self.assertEqual(certificate.call_args_list[0].args, ("/opt/cats/certs/portal", "portal.example"))
            self.assertEqual(certificate.call_args_list[1].args, ("/opt/cats/certs/oci-proxy", "registry.example"))
            if mode == "main":
                self.assertEqual(values["CATS_SCAN_JOB_TIMEOUT"], "10800")
                self.assertRegex(values["CATS_KIND_NODE_IMAGE"], r"^kindest/node:[^@]+@sha256:[0-9a-f]{64}$")
                self.assertNotIn("CATS_DEPLOYMENT_KIND_NODE_IMAGE", values)

    def test_replica_setup_migrates_legacy_image_without_shadowing_shared_override(self):
        existing = {"CATS_REPLICA_IMAGE": "registry.example/cats:legacy",
                    "CATS_PORTAL_HOSTNAME": "portal.example", "CATS_OCI_HOSTNAME": "registry.example"}
        for shared in (None, "", "registry.example/cats:approved"):
            previous = dict(existing)
            if shared is not None:
                previous["CATS_IMAGE"] = shared
            with self.subTest(shared=shared), \
                 patch.object(setup, "ask", side_effect=lambda label, default="", secret=False: default), \
                 patch.object(setup, "certificate", side_effect=lambda directory, name: directory):
                values = setup.gather("replica", previous, {})
            self.assertEqual(values["CATS_IMAGE"], shared or existing["CATS_REPLICA_IMAGE"])
            self.assertEqual(values["CATS_REPLICA_IMAGE"], existing["CATS_REPLICA_IMAGE"])
            self.assertEqual(previous.get("CATS_IMAGE"), shared)

    def test_bundle_image_sets_shared_image_for_both_modes_and_preserves_legacy_value(self):
        existing = {"CATS_IMAGE": "cats:previous", "CATS_REPLICA_IMAGE": "cats:legacy",
                    "CATS_PORTAL_HOSTNAME": "portal.example", "CATS_OCI_HOSTNAME": "registry.example"}
        manifest = {"images": [{"role": "cats", "archive_reference": "cats-setup/cats:release"}]}
        for mode in ("main", "replica"):
            with self.subTest(mode=mode), \
                 patch.object(setup, "ask", side_effect=lambda label, default="", secret=False: default), \
                 patch.object(setup, "certificate", side_effect=lambda directory, name: directory):
                values = setup.gather(mode, existing, manifest)
            self.assertEqual(values["CATS_IMAGE"], "cats-setup/cats:release")
            self.assertEqual(values["CATS_REPLICA_IMAGE"], "cats:legacy")

    def test_files_only_suggestions_keep_target_images_and_legacy_replica_override(self):
        manifest = {"files_only": True, "images": [
            {"role": "cats", "archive_reference": "cats:suggested"},
            {"role": "nginx", "archive_reference": "nginx:suggested"}]}
        for mode, image_settings, expected in (
                ("main", {"CATS_IMAGE": "cats:target"}, "cats:target"),
                ("replica", {"CATS_IMAGE": "cats:target", "CATS_REPLICA_IMAGE": "cats:legacy"}, "cats:target"),
                ("replica", {"CATS_IMAGE": "", "CATS_REPLICA_IMAGE": "cats:legacy"}, "cats:legacy")):
            existing = {"CATS_PORTAL_HOSTNAME": "portal.example", "CATS_OCI_HOSTNAME": "registry.example",
                        "CATS_NGINX_IMAGE": "nginx:target", **image_settings}
            with self.subTest(mode=mode, image_settings=image_settings), \
                 patch.object(setup, "ask", side_effect=lambda label, default="", secret=False: default), \
                 patch.object(setup, "certificate", side_effect=lambda directory, name: directory):
                values = setup.gather(mode, existing, manifest)
            self.assertEqual(values["CATS_IMAGE"], expected)
            self.assertEqual(values["CATS_NGINX_IMAGE"], "nginx:target")

    def test_unselected_files_only_image_prompts_for_target_reference(self):
        existing = {"CATS_PORTAL_HOSTNAME": "portal.example", "CATS_OCI_HOSTNAME": "registry.example"}
        manifest = {"files_only": True, "images": [{"role": "cats", "archive_reference": None}]}
        prompts = []

        def answer(label, default="", secret=False):
            if label.startswith("Full CATS image"):
                prompts.append(default)
                return "cats:already-local"
            return default

        for mode in ("main", "replica"):
            with self.subTest(mode=mode), patch.object(setup, "ask", side_effect=answer), \
                 patch.object(setup, "certificate", side_effect=lambda directory, name: directory):
                values = setup.gather(mode, existing, manifest)
            self.assertEqual(values["CATS_IMAGE"], "cats:already-local")
        self.assertEqual(prompts, ["", ""])

    def test_setup_keeps_existing_overrides_and_migrates_legacy_node_image(self):
        existing = {"CATS_IMAGE": "cats:test", "CATS_PORTAL_HOSTNAME": "portal.example",
                    "CATS_OCI_HOSTNAME": "registry.example", "CATS_PORTAL_CERT_DIR": "/existing/portal",
                    "CATS_OCI_CERT_DIR": "/existing/oci", "CATS_SCAN_JOB_TIMEOUT": "7200",
                    "CATS_DEPLOYMENT_KIND_NODE_IMAGE": "registry.example/kind:legacy"}
        for public in (None, "", "registry.example/kind:approved"):
            previous = dict(existing)
            if public is not None:
                previous["CATS_KIND_NODE_IMAGE"] = public
            with self.subTest(public=public), \
                 patch.object(setup, "ask", side_effect=lambda label, default="", secret=False: default), \
                 patch.object(setup, "certificate", side_effect=lambda directory, name: directory):
                values = setup.gather("main", previous, {})
            for key in ("CATS_PORTAL_CERT_DIR", "CATS_OCI_CERT_DIR", "CATS_SCAN_JOB_TIMEOUT",
                        "CATS_DEPLOYMENT_KIND_NODE_IMAGE"):
                self.assertEqual(values[key], existing[key])
            self.assertEqual(values["CATS_KIND_NODE_IMAGE"], public or existing["CATS_DEPLOYMENT_KIND_NODE_IMAGE"])

    def test_setup_saves_selected_node_image_without_enabling_validation_or_loading_it(self):
        existing = {"CATS_IMAGE": "cats:test", "CATS_PORTAL_HOSTNAME": "portal.example",
                    "CATS_OCI_HOSTNAME": "registry.example"}
        selected = "registry.example/kind:approved"
        def answer(label, default="", secret=False):
            return selected if label.startswith("Kind node image tag or digest") else default
        with patch.object(setup, "ask", side_effect=answer), \
             patch.object(setup, "certificate", side_effect=lambda directory, name: directory), \
             patch.object(setup, "run", side_effect=AssertionError("Node images are optional at setup time")):
            values = setup.gather("main", existing, {})
        self.assertEqual(values["CATS_KIND_NODE_IMAGE"], selected)
        self.assertEqual(values["CATS_DEPLOYMENT_VALIDATION_ENABLED"], "false")

    def test_existing_project_requires_original_secrets_even_with_partial_env(self):
        with patch.object(setup, "run", side_effect=["cats_db\n", ""]):
            with self.assertRaisesRegex(setup.SetupError, "original secrets"):
                setup.ensure_no_unclaimed_project("cats", {"COMPOSE_PROJECT_NAME": "cats"})
        with patch.object(setup, "run", side_effect=["cats_db\n", ""]):
            setup.ensure_no_unclaimed_project("cats", {"POSTGRES_PASSWORD": "original", "CATS_CONFIG_ENCRYPTION_KEY": "original"})

    def test_unclaimed_project_without_volumes_still_detects_running_containers(self):
        with patch.object(setup, "run", side_effect=["", "container-id"]), self.assertRaises(setup.SetupError):
            setup.ensure_no_unclaimed_project("cats", {})

    def test_hostnames_match_ingress_contract(self):
        for value in ("portal", "https://portal.example", "portal.example:443", "*.example", "foo..example", "foo.-example"):
            with self.subTest(value=value), self.assertRaises(setup.SetupError):
                setup.hostname(value)
        self.assertEqual(setup.hostname("Portal.Example.COM"), "portal.example.com")

    def test_certificate_mismatch_rejected_even_when_openssl_exits_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            for name in ("tls.crt", "tls.key"):
                (Path(directory) / name).write_text("fixture")
            with patch.object(setup.ssl, "SSLContext"), patch.object(setup, "run", side_effect=["Certificate will not expire", "Hostname portal.example does NOT match certificate"]):
                with self.assertRaisesRegex(setup.SetupError, "does not cover"):
                    setup.certificate(directory, "portal.example")

    def test_future_certificate_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            for name in ("tls.crt", "tls.key"):
                (Path(directory) / name).write_text("fixture")
            with patch.object(setup.ssl, "SSLContext"), patch.object(setup, "run", side_effect=["", "Hostname portal.example does match certificate", "notBefore=Jan  1 00:00:00 2999 GMT"]):
                with self.assertRaisesRegex(setup.SetupError, "not valid yet"):
                    setup.certificate(directory, "portal.example")

    def test_bundle_rejects_tampering_wrong_mode_and_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "payload").write_bytes(b"original")
            manifest = {"schema_version": 1, "mode": "main", "files": {"payload": hashlib.sha256(b"original").hexdigest()}}
            (root / "manifest.json").write_text(json.dumps(manifest))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(setup.verify_bundle(root, "main"), manifest)
            with self.assertRaises(setup.SetupError):
                setup.verify_bundle(root, "replica")
            (root / "payload").write_bytes(b"changed")
            with self.assertRaisesRegex(setup.SetupError, "checksum"):
                setup.verify_bundle(root, "main")
            manifest["files"] = {"../outside": "x"}
            (root / "manifest.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(setup.SetupError, "unsafe"):
                setup.verify_bundle(root, "main")

    def test_replica_does_not_load_worker_apparmor(self):
        self.assertFalse(setup.apparmor_needed("replica", {"SecurityOptions": ["name=apparmor"]}))
        with patch.object(setup, "ROOT", ROOT):
            command = setup.compose_command("replica", Path("replica.env"), {"COMPOSE_PROJECT_NAME": "cats-replica"}, False, [])
        self.assertNotIn(str(ROOT / "deploy/compose.worker-apparmor.yaml"), command)
        self.assertNotIn("--project-directory", command)

    def test_active_remote_context_cannot_hide_behind_local_docker_host(self):
        replies = ["2.39.4", json.dumps([{"Endpoints": {"docker": {"Host": "ssh://remote.example"}}}])]
        with patch.object(setup.sys, "platform", "linux"), patch.object(setup.shutil, "which", return_value="tool"), \
             patch.dict(os.environ, {"DOCKER_CONTEXT": "remote", "DOCKER_HOST": "unix:///var/run/docker.sock"}), \
             patch.object(setup, "run", side_effect=replies) as mocked:
            with self.assertRaisesRegex(setup.SetupError, "local Docker context"):
                setup.docker_host()
            self.assertEqual(mocked.call_args.args[0], ["docker", "context", "inspect", "remote"])

    def test_run_and_saved_launcher_pin_local_daemon_and_exclude_secrets(self):
        values = {"COMPOSE_PROJECT_NAME": "cats", "POSTGRES_PASSWORD": "never-print-this",
                  "CATS_SETUP_DOCKER_HOST": "unix:///var/run/docker.sock"}
        command = setup.compose_command("main", Path("/secure/cats.env"), values, True, [])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "launcher.sh"
            setup.write_launcher(path, command, values)
            text = path.read_text()
            self.assertIn("--host unix:///var/run/docker.sock", text)
            self.assertIn("-u DOCKER_CONTEXT", text)
            self.assertNotIn(values["POSTGRES_PASSWORD"], text)
        result = Mock(returncode=0, stdout="ok")
        with patch.object(setup, "DOCKER_ENDPOINT", "unix:///var/run/docker.sock"), \
             patch.dict(os.environ, {"DOCKER_CONTEXT": "remote"}), patch.object(setup.subprocess, "run", return_value=result) as invoked:
            setup.run(["docker", "image", "inspect", "cats:local"])
            self.assertEqual(invoked.call_args.args[0][:3], ["docker", "--host", "unix:///var/run/docker.sock"])
            self.assertNotIn("DOCKER_CONTEXT", invoked.call_args.kwargs["env"])

    def test_image_identity_and_architecture_checked_after_load(self):
        image = {"Id": "sha256:one", "Os": "linux", "Architecture": "amd64"}
        with patch.object(setup, "run", return_value=json.dumps([image])):
            setup.image_ready("cats:local", {"Architecture": "x86_64"}, False, "sha256:one")
            with self.assertRaisesRegex(setup.SetupError, "identity"):
                setup.image_ready("cats:local", {"Architecture": "x86_64"}, False, "sha256:two")
            with self.assertRaisesRegex(setup.SetupError, "architecture"):
                setup.image_ready("cats:local", {"Architecture": "arm64"}, False)

    def test_image_identity_accepts_verified_docker_store_formats_only(self):
        identities = tuple("sha256:" + value * 64 for value in "abc")
        for identity in identities + ("sha256:" + "d" * 64,):
            image = {"Id": identity, "Os": "linux", "Architecture": "amd64"}
            with patch.object(setup, "run", return_value=json.dumps([image])):
                if identity in identities:
                    setup.image_ready("cats:local", {"Architecture": "amd64"}, False, identities)
                else:
                    with self.assertRaisesRegex(setup.SetupError, "identity"):
                        setup.image_ready("cats:local", {"Architecture": "amd64"}, False, identities)

    def test_private_write_does_not_follow_existing_symlink(self):
        if os.name == "nt":
            self.skipTest("Windows symlink privilege is not required by the Linux installer tests")
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            target.write_text("preserve")
            link = Path(directory) / "link"
            link.symlink_to(target)
            with self.assertRaises(setup.SetupError):
                setup.private_write(link, "replace")
            self.assertEqual(target.read_text(), "preserve")

    def test_configure_only_upgrade_preserves_backup_and_never_starts_services(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env_file = root / "replica.env"
            original = "# Original operator settings\nPOSTGRES_PASSWORD='unchanged password'\n"
            env_file.write_text(original, encoding="utf-8")
            values = {"COMPOSE_PROJECT_NAME": "cats-replica", "POSTGRES_PASSWORD": "unchanged password",
                      "CATS_BOOTSTRAP_USERNAME": "admin", "CATS_BOOTSTRAP_PASSWORD": "kept-private"}
            info = {"_SetupEndpoint": "unix:///var/run/docker.sock", "Architecture": "amd64"}
            with patch.object(setup, "verify_bundle", return_value={}), patch.object(setup, "docker_host", return_value=info), \
                 patch.object(setup, "gather", return_value=values), patch.object(setup, "ensure_no_unclaimed_project"), \
                 patch.object(setup, "run") as invoked, patch.object(setup, "load_apparmor") as policy, \
                 patch.object(setup, "yes", side_effect=AssertionError("No operational prompts in configure-only")), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(setup.main(["--mode", "replica", "--env-file", str(env_file), "--configure-only"]), 0)
                self.assertEqual(setup.parse_env(env_file.read_text())["POSTGRES_PASSWORD"], "unchanged password")
                self.assertEqual(env_file.with_name("replica.env.pre-setup").read_text(), original)
                self.assertTrue((root / "replica-compose.sh").is_file())
                self.assertEqual(invoked.call_count, 1)
                self.assertEqual(invoked.call_args.args[0][-2:], ["config", "--quiet"])
                policy.assert_not_called()
                # A rerun must preserve the initial recovery copy.
                setup.main(["--mode", "replica", "--env-file", str(env_file), "--configure-only"])
                self.assertEqual(env_file.with_name("replica.env.pre-setup").read_text(), original)

    def test_full_image_requires_supported_architecture_for_both_modes(self):
        for mode in ("main", "replica"):
            with self.subTest(mode=mode), \
                 patch.object(setup, "verify_bundle", return_value={}), \
                 patch.object(setup, "docker_host", return_value={"_SetupEndpoint": "unix:///var/run/docker.sock", "Architecture": "arm64"}), \
                 patch.object(setup, "gather") as gather, contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(setup.SetupError, "Linux amd64"):
                    setup.main(["--mode", mode, "--configure-only"])
                gather.assert_not_called()

    def test_apparmor_host_requires_qualified_os_and_enforcing_loaded_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            release = Path(directory) / "os-release"
            release.write_text('ID=ubuntu\nVERSION_ID="22.04"\n')
            with self.assertRaisesRegex(setup.SetupError, "qualified for Ubuntu 24.04"):
                setup.apparmor_needed("main", {"SecurityOptions": ["name=apparmor"]}, os_release=release)
        with patch.object(setup.os, "geteuid", return_value=0, create=True), \
             patch.object(setup.shutil, "which", return_value="apparmor_parser"), \
             patch.object(setup, "run", side_effect=["", "", "cats-worker-actions (complain)\n"]), \
             contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(setup.SetupError, "not enforcing"):
                setup.load_apparmor()


@unittest.skipUnless(shutil.which("docker"), "Docker Compose CLI not installed")
class ComposeContracts(unittest.TestCase):
    def test_real_compose_environment_preserves_special_passwords(self):
        values = {"VALUE": "$HOME ${INJECT} back\\'quote ends\\"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "compose.yaml").write_text("services:\n  test:\n    image: example:local\n    environment:\n      VALUE: ${VALUE}\n")
            (root / "test.env").write_text(setup.serialize_env(values), encoding="utf-8")
            result = subprocess.run(["docker", "compose", "--env-file", str(root / "test.env"), "-f", str(root / "compose.yaml"), "config", "--environment"],
                                    env=setup.clean_environment(values), text=True, capture_output=True, check=True)
            self.assertIn("VALUE=" + values["VALUE"], result.stdout.splitlines())

    def test_main_overlay_merges_policy_and_resolves_bundled_paths(self):
        values = setup.parse_env((ROOT / "templates/main.env.example").read_text())
        values.update(CATS_PORTAL_HOSTNAME="portal.test.example", CATS_OCI_HOSTNAME="registry.test.example",
                      CATS_IMAGE="cats:test", POSTGRES_PASSWORD="database-password-for-test",
                      CATS_CONFIG_ENCRYPTION_KEY=base64.urlsafe_b64encode(b"a" * 32).decode(), COMPOSE_PROJECT_NAME="cats-setup-contract")
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / "test.env"
            env_file.write_text(setup.serialize_env(values), encoding="utf-8")
            command = setup.compose_command("main", env_file, values, True, [])
            result = subprocess.run(command + ["config", "--format", "json"], env=setup.clean_environment(values), text=True, capture_output=True, check=True)
            config = json.loads(result.stdout)
            for worker in setup.WORKERS:
                self.assertEqual(config["services"][worker]["security_opt"],
                                 ["no-new-privileges:true", "seccomp=../deploy/discovery-seccomp.json", "apparmor=cats-worker-actions"])
            mount = next(m for m in config["services"]["discovery-worker"]["volumes"] if m["target"] == "/opt/discovery-mirror")
            self.assertEqual(Path(mount["source"]).resolve(), (ROOT / "deploy/discovery-mirror").resolve())


if __name__ == "__main__":
    unittest.main()
