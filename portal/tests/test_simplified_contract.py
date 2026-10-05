from datetime import datetime, timezone
from types import SimpleNamespace as N

from app.findings_query import group_simplified_findings
from app.frontend import _service_data


def finding(identity, cve, severity, observations):
    return N(id=identity, cve=cve, severity=severity, observations=observations)


def observation(identity, execution=7, package="openssl", fixed="3", image=None, **evidence):
    return N(id=identity, execution_id=execution, package=package, fixed_version=fixed,
             image=image, evidence=evidence)


def test_canonical_grouping_uses_current_latest_evidence_and_deduplicates_cve():
    rows = [
        finding(5, " cve-b ", "low", [observation(3, image="b", remediation="Update"), observation(99, execution=6, package="old")]),
        finding(2, "CVE-A", "HIGH", [observation(4, fixed="4", image="a", remediation="Update")]),
        finding(8, "CVE-B", "critical", [observation(5, fixed="5", image="a", remediation="Update")]),
        finding(9, "CVE-C", "medium", [observation(100, execution=6, remediation="Other", image="past")]),
    ]
    due = {5: datetime(2026, 10, 10, tzinfo=timezone.utc), 2: datetime(2026, 10, 9, tzinfo=timezone.utc)}
    groups = group_simplified_findings(rows, N(id=7), due)
    group = next(item for item in groups if item["remediation"] == "Update")
    assert group["cves"] == ["CVE-A", "CVE-B"]
    assert group["finding_ids"] == [2, 5]
    assert group["fixed_version"] == "3, 4, 5"
    assert group["images"] == ["a", "b"]
    assert group["severity"] == "critical"
    assert group["due"] == due[2]
    assert next(item for item in groups if item["remediation"] == "Other")["images"] == []


def test_canonical_defaults_and_first_missing_due_are_retained():
    rows = [finding(1, "", "HIGH", []), finding(2, "CVE-A", "high", [])]
    group = group_simplified_findings(rows, None, {2: datetime.now(timezone.utc)})[0]
    assert group["package"] == "Package update"
    assert group["fixed_version"] == "Latest fixed version"
    assert group["remediation"] == "Update the affected package to the fixed version."
    assert group["severity"] == "HIGH"
    assert group["due"] is None
    assert group["finding_ids"] == [2]


def test_simplified_dto_never_traverses_unbounded_group_collections():
    class ForbiddenCollection:
        def __iter__(self):
            raise AssertionError("summary must not traverse members")

    context = {"view": {"service": N(id=1, groups=[])}, "simplified_findings": [{
        "group_id": "opaque", "member_count": 100000, "representative_cve": "CVE-A",
        "package": "openssl", "image_count": 20000, "cves": ForbiddenCollection(),
        "finding_ids": ForbiddenCollection(), "images": ForbiddenCollection(),
        "fixed_versions": ForbiddenCollection(), "severities": ForbiddenCollection(),
    }]}
    data = {"can": {}}
    _service_data(data, context, None, {})
    group = data["simplified_findings"][0]
    assert group["member_count"] == 100000
    assert group["image_count"] == 20000
    assert not {"cves", "finding_ids", "images", "fixed_versions", "severities"}.intersection(group)


def test_sql_group_summary_matches_canonical_versions_images_due_and_order(monkeypatch):
    from datetime import timedelta
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from app import main, simplified_queries
    from app.database import Base
    from app.models import Service, Finding, FindingObservation, Execution
    monkeypatch.setattr(main, 'kev_cves', lambda: set())
    monkeypatch.setattr(main, 'epss_scores', lambda: {})
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    now = datetime(2026, 10, 4, 12, 0, 0, 123456, tzinfo=timezone.utc)
    cfg = dict(main.CONFIG_DEFAULTS, compliance_mode='raw', overdue_days='90',
               raw_due_rules='[{"severity":"critical","days":30}]')
    with Session(engine) as db:
        service = Service(service_key='contract', name='Contract')
        db.add(service); db.flush()
        scan = Execution(service_id=service.id, execution_key='contract', scanned_at=now, complete=True, raw_payload={})
        previous = Execution(service_id=service.id, execution_key='previous', scanned_at=now, complete=True, raw_payload={})
        db.add_all([scan, previous]); db.flush()
        rows, due_dates = [], {}
        for index, (package, fixed, remediation, severity) in enumerate([
            ('Straße', '2', 'Update', 'High'), ('Straße', '10', 'Update', 'critical'),
            ('Straße', '10', 'Update', 'LOW'), ('Straße', '15', 'Other', 'HIGH'),
            ('fallback', '3', 'Old', 'High'), ('İtem', '2', None, 'High'),
        ]):
            started = now - timedelta(days=index + 1)
            finding = Finding(service_id=service.id, cve=f'CVE-{5-index}', severity=severity,
                              active=True, first_seen=started, episode_started=started, last_seen=now)
            db.add(finding); db.flush()
            obs = FindingObservation(finding_id=finding.id, execution_id=previous.id if package == 'fallback' else scan.id,
                package=package, fixed_version=fixed, image=f'image-{index%2}',
                evidence={'recommendation': remediation} if remediation else {})
            db.add(obs); db.flush()
            rows.append(N(id=finding.id, cve=finding.cve, severity=severity, observations=[obs]))
            due_dates[finding.id] = started + timedelta(days=30 if severity == 'critical' else 90)
        db.commit()
        expected = group_simplified_findings(rows, scan, due_dates)
        actual, info, _ = simplified_queries.group_page(db, service, scan, now, cfg, page_size=2)
        assert info['total_items'] == len(expected)
        for summary, canonical in zip(actual, expected[:2]):
            for key in ('package', 'remediation', 'fixed_version', 'severity', 'due'):
                assert summary[key] == canonical[key]
            assert summary['member_count'] == len(canonical['cves'])
            assert summary['representative_cve'] == canonical['cves'][0]
            assert summary['representative_finding_id'] == canonical['finding_ids'][0]
            assert summary['image_count'] == len(canonical['images'])
        later, _, _ = simplified_queries.group_page(db, service, scan, now, cfg, page=2, page_size=2)
        assert [row['remediation'] for row in actual + later] == [row['remediation'] for row in expected]
        for summary, canonical in zip(actual + later, expected):
            for key in ('package', 'remediation', 'fixed_version', 'severity', 'due'):
                assert summary[key] == canonical[key]
            assert summary['image_count'] == len(canonical['images'])
        clamped, page, _ = simplified_queries.group_page(db, service, scan, now, cfg, page=1999, page_size=2)
        assert page['page'] == 2
        assert clamped == later
        empty, page, _ = simplified_queries.group_page(db, service, scan, now, cfg, finding_type='configuration')
        assert empty == [] and page['total_items'] == 0
    engine.dispose()
