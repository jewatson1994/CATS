"""Direct ORM transfer checks; no server, worker, or shared database."""
from copy import deepcopy
from datetime import datetime, timezone, timedelta
import unittest
from unittest.mock import patch

from sqlalchemy import create_engine, select, event, DateTime, Integer, Boolean, JSON
from sqlalchemy.orm import Session

from app.database import Base
from app import models as m
from app import service_transfer as t


class TransferCoreTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite://")
        @event.listens_for(self.engine, "connect")
        def foreign_keys(connection, _):
            connection.execute("PRAGMA foreign_keys=ON")
        Base.metadata.create_all(self.engine)
        self.db = Session(self.engine)
        self.addCleanup(self.engine.dispose)
        self.addCleanup(self.db.close)
        self.user = m.User(username="importer", display_name="Importer")
        self.service = m.Service(service_key="original", name="Original")
        self.db.add_all([self.user, self.service]); self.db.flush()
        self.now = datetime(2025, 1, 2, tzinfo=timezone.utc)
        self.execution = self.execution_at(self.now, "current")

    def execution_at(self, timestamp, key):
        raw = dict(execution_id=key, scanned_at=timestamp.isoformat(), complete=True,
                   fixable_only=False, service=dict(id="original", name="Original", version="1"))
        row = m.Execution(service_id=self.service.id, execution_key=key, scanned_at=timestamp,
                          complete=True, raw_payload=raw)
        self.db.add(row); self.db.flush()
        return row

    def exported(self):
        return t.parse_service(t.export_service(self.db, self.service, "tester"))

    def test_roundtrip_references_jobs_and_provenance(self):
        finding = m.Finding(service_id=self.service.id, cve="CVE-2025-1234", severity="High",
                            first_seen=self.now, episode_started=self.now, last_seen=self.now)
        artifact = m.ServiceArtifact(service_id=self.service.id, artifact_type="helm", artifact_name="chart",
                                     source_execution_id=self.execution.id, source_reference="current")
        entry = m.DependencyWatchlistEntry(name="example", enabled=True)
        self.db.add_all([finding, artifact, entry]); self.db.flush()
        revision = m.ServiceArtifactRevision(artifact_id=artifact.id, revision_number=1,
                    files={"values.yaml": "replicas: 1", ".env": "PASSWORD=bad"}, checksum="x")
        self.db.add(revision); self.db.flush()
        self.db.add_all([
            m.FindingObservation(finding_id=finding.id, execution_id=self.execution.id, image="image", evidence={"password": "bad", "ok": True}),
            m.RemediationExecution(service_id=self.service.id, requested_by_id=self.user.id, job_key="job", finding_type="vulnerability", finding_id=finding.id, status="running"),
            m.DeploymentValidationRun(service_id=self.service.id, run_key="run", execution_id=self.execution.id, artifact_revision_id=revision.id, status="RUNNING", cluster_name="real-cluster", cleanup_status="FAILED"),
            m.DependencyWatchlistMatch(service_id=self.service.id, entry_id=entry.id, execution_id=self.execution.id, component_name="example", image="image"),
            m.ServiceMetadata(service_id=self.service.id, values={"owner": "original"}),
        ]); self.db.flush()
        manifest, state = self.exported()
        restored = t.restore_service(self.db, state, "restored", self.user.id)
        rem = self.db.scalar(select(m.RemediationExecution).where(m.RemediationExecution.service_id == restored.id))
        self.assertIsNone(rem)
        run = self.db.scalar(select(m.DeploymentValidationRun).where(m.DeploymentValidationRun.service_id == restored.id))
        self.assertIsNone(run)
        match = self.db.scalar(select(m.DependencyWatchlistMatch).where(m.DependencyWatchlistMatch.service_id == restored.id))
        self.assertIsNone(match)
        self.assertTrue(self.db.get(m.DependencyWatchlistEntry, entry.id).enabled)
        art = self.db.scalar(select(m.ServiceArtifact).where(m.ServiceArtifact.service_id == restored.id))
        self.assertIsNone(art.source_execution_id)
        self.assertIsNone(self.db.scalar(select(m.Execution).where(m.Execution.service_id == restored.id)))
        self.assertEqual(manifest["schema_version"], 3)
        self.assertEqual(manifest["semantics"], "authoritative_inputs")
        manifest2, state2 = t.parse_service(t.export_service(self.db, restored, "tester"))
        self.assertEqual(len(state2["records"]["service_transfer_provenance"]), 0)
        self.assertEqual(len(self.db.scalars(select(m.ServiceTransferProvenance).where(
            m.ServiceTransferProvenance.service_id == restored.id)).all()), 1)
        self.assertNotIn(".env", state2["records"]["service_artifact_revisions"][0]["files"])
        self.assertEqual(state2["records"]["finding_observations"], [])

    def test_history_duplicates_and_current_protection(self):
        state = {"records": t.snapshot(self.db, self.service)}
        self.assertEqual(t.plan_history(self.db, state, self.service), ([], 1))
        new = deepcopy(state["records"]["executions"][0])
        new["raw_payload"]["service"]["version"] = "older"
        state["records"]["executions"].append(new)
        with self.assertRaisesRegex(ValueError, "precede"):
            t.add_history(self.db, state, self.service)
        new["scanned_at"] = (self.now - timedelta(days=1)).isoformat()
        new["raw_payload"]["scanned_at"] = new["scanned_at"]
        self.assertEqual(t.add_history(self.db, state, self.service), 1)
        self.assertEqual(t.add_history(self.db, state, self.service), 0)
        latest = self.db.scalar(select(m.Execution).where(m.Execution.service_id == self.service.id).order_by(m.Execution.scanned_at.desc()))
        self.assertEqual(latest.id, self.execution.id)

    def test_export_enforces_record_limit(self):
        self.db.add(m.ServiceMetadata(service_id=self.service.id, values={"manual": True})); self.db.flush()
        with patch.dict("os.environ", {"CATS_BUNDLE_MAX_RECORDS": "1"}):
            with self.assertRaisesRegex(ValueError, "record count"):
                t.export_service(self.db, self.service, "tester")

    def test_export_rejects_oversized_manifest(self):
        with self.assertRaisesRegex(ValueError, "manifest exceeds"):
            t.export_service(self.db, self.service, "x" * 65536)

    def test_export_ignores_derived_validation_artifact(self):
        self.db.add(m.DeploymentValidationRun(service_id=self.service.id, run_key="dangling",
                    status="VERIFIED", artifact_reference="artifact:999:r1"))
        self.db.flush()
        _, state = self.exported()
        self.assertEqual(state["records"]["deployment_validation_runs"], [])

    def test_malformed_record_category_is_rejected(self):
        manifest, state = self.exported()
        state["records"]["executions"] = 42
        with self.assertRaisesRegex(ValueError, "categories must be lists"):
            t.validate_state(state, manifest)

    def test_reject_bad_shapes_and_cross_service_references(self):
        manifest, state = self.exported()
        state["records"]["services"][0]["name"] = []
        with self.assertRaises(ValueError): t.validate_state(state, manifest)
        manifest, state = self.exported()
        state["records"]["services"][0]["service_key"] = "different"
        with self.assertRaises(ValueError): t.validate_state(state, manifest)
        for sources in (["bad"], {"../escape": "bad"}, {"ok": {"bad": 1}}):
            with self.assertRaises(ValueError): t.safe_sources(sources, [])

    def test_every_domain_table_roundtrips_with_foreign_keys_enabled(self):
        version = m.ServiceVersion(service_id=self.service.id, version="1", created_at=self.now)
        self.db.add(version); self.db.flush()
        self.execution.service_version_id = version.id
        self.service.current_version_id = version.id
        parents = {"services": self.service.id, "service_versions": version.id,
                   "executions": self.execution.id, "users": self.user.id}
        for model in t.MODELS[3:]:
            values = {}
            for column in model.__table__.columns:
                if column.name == "id" or column.nullable or column.default is not None:
                    continue
                if column.foreign_keys:
                    parent = next(iter(column.foreign_keys)).column.table.name
                    values[column.name] = parents[parent]
                elif isinstance(column.type, DateTime): values[column.name] = self.now
                elif isinstance(column.type, Boolean): values[column.name] = True
                elif isinstance(column.type, Integer): values[column.name] = 1
                elif isinstance(column.type, JSON): values[column.name] = {}
                else: values[column.name] = "test"
            row = model(**values)
            self.db.add(row); self.db.flush()
            parents[model.__tablename__] = row.service_id if model is m.ServiceMetadata else row.id
        _, state = self.exported()
        self.assertTrue(all(state["records"][name] for name in t.PORTABLE))
        restored = t.restore_service(self.db, state, "all-domains", self.user.id)
        _, copied = t.parse_service(t.export_service(self.db, restored, "tester"))
        for name in t.TABLES:
            expected = (2 if name == "service_transfer_provenance" else 1) if name in t.PORTABLE else 0
            self.assertEqual(len(copied["records"][name]), expected, name)

    def test_legacy_restore_projects_derived_state_and_preserves_human_poam(self):
        finding = m.Finding(service_id=self.service.id, cve="CVE-2025-1111", severity="High",
                            first_seen=self.now, episode_started=self.now, last_seen=self.now)
        self.db.add(finding); self.db.flush()
        self.db.add(m.PoamEntry(service_id=self.service.id, finding_id=finding.id, item_type="vulnerability",
                    title="Human plan", description="Retain this", remediation="Update", created_by_id=self.user.id))
        self.db.flush()
        state = {"records": t.snapshot(self.db, self.service)}
        restored = t.restore_service(self.db, state, "legacy-inputs", self.user.id)
        self.assertIsNone(self.db.scalar(select(m.Execution).where(m.Execution.service_id == restored.id)))
        self.assertIsNone(self.db.scalar(select(m.Finding).where(m.Finding.service_id == restored.id)))
        poam = self.db.scalar(select(m.PoamEntry).where(m.PoamEntry.service_id == restored.id))
        self.assertEqual(poam.title, "Human plan")
        self.assertIsNone(poam.finding_id)
        self.assertEqual(poam.supplemental_fields["imported_finding_references"]["finding_id"], finding.id)

    def test_original_sources_retained_without_execution_or_embedded_secrets(self):
        self.execution.raw_payload = {**self.execution.raw_payload, "helm_source_files": {
            "service.yaml": "services:\n  chart:\n    enabled: false\n    password: |\n      TOP_SECRET\n    values: {token: OTHER_SECRET, replicas: 2}\n",
            "values.yaml": "replicas: 2\n"}, "helm_values_files": ["values.yaml"]}
        self.db.flush()
        manifest, state = self.exported()
        serialized = str(state)
        self.assertNotIn("TOP_SECRET", serialized)
        self.assertNotIn("OTHER_SECRET", serialized)
        self.assertEqual(state["records"]["executions"], [])
        self.assertEqual(len(state["records"]["service_artifact_revisions"]), 1)
        restored = t.restore_service(self.db, state, "source-inputs", self.user.id)
        artifact = self.db.scalar(select(m.ServiceArtifact).where(m.ServiceArtifact.service_id == restored.id))
        self.assertEqual(artifact.source_metadata["helm_values_files"], ["values.yaml"])

    def test_import_resets_image_assessment(self):
        self.db.add(m.ServiceImage(service_id=self.service.id, image_reference="registry/example:1", scan_status="completed", scan_job_id="foreign-worker", last_scanned_at=self.now))
        self.db.flush()
        _, state = self.exported()
        restored = t.restore_service(self.db, state, "image-inputs", self.user.id)
        image = self.db.scalar(select(m.ServiceImage).where(m.ServiceImage.service_id == restored.id))
        self.assertEqual(image.image_reference, "registry/example:1")
        self.assertEqual(image.scan_status, "never_scanned")
        self.assertIsNone(image.scan_job_id)


if __name__ == "__main__":
    unittest.main()
