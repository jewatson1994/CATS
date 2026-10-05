from types import SimpleNamespace as N
from sqlalchemy import create_engine, insert
from sqlalchemy.orm import Session
from app.database import Base
from app.models import Finding, FindingObservation, Service, Execution, utcnow
from app import findings_query as queries


def test_100000_group_page_loads_support_for_only_selected_groups(monkeypatch):
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    findings = [N(id=index + 1, cve=f'CVE-{index}', severity='High', active=True,
        observations=[N(id=index + 1, execution_id=1, package=f'pkg-{index:06}',
            fixed_version='2', evidence={}, image='image')]) for index in range(100000)]
    calls = []
    original = queries.load_page_support
    def support(db, service_id, candidates, latest):
        candidates = list(candidates)
        calls.append(len(candidates))
        return original(db, service_id, candidates, latest)
    monkeypatch.setattr(queries, 'load_page_support', support)
    with Session(engine) as db:
        rows, page = queries.page_simplified_findings(db, 1, findings, N(id=2), {}, 1999, 50)
        assert page == {'page': 1999, 'total_items': 100000, 'total_pages': 2000}
        assert [r['package'] for r in rows] == [f'pkg-{i:06}' for i in range(99900, 99950)]
        assert calls == []
        assert not db.identity_map
        assert all(not row['images'] for row in rows)
    engine.dispose()


def test_current_group_keys_unicode_json_and_fallback_match_legacy():
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    now = utcnow()
    with Session(engine) as db:
        service = Service(service_key='groups', name='Groups')
        db.add(service); db.flush()
        scan = Execution(service_id=service.id, execution_key='groups', scanned_at=now, complete=True, raw_payload={})
        db.add(scan); db.flush()
        findings = []
        for index, package in enumerate(['Straße', 'STRASSE', 'İtem', 'Äpfel', 'Äpfel']):
            finding = Finding(service_id=service.id, cve=f'CVE-{index}', severity='High',
                first_seen=now, episode_started=now, last_seen=now)
            db.add(finding); db.flush()
            observation = N(id=100 + index, finding_id=finding.id, execution_id=scan.id,
                image='image', package=package, installed_version='1', fixed_version=str(index),
                evidence={'remediation': {'nested': [1, True]}})
            db.execute(insert(FindingObservation), [dict(vars(observation))])
            findings.append(N(id=finding.id, cve=finding.cve, severity='High', active=True,
                observations=[N(id=index + 1, execution_id=-1, image='old', package='Old',
                    fixed_version='old', evidence={})]))
        db.commit()
        service_id, selected_scan = service.id, N(id=scan.id)
        db.expunge_all()
        queries.load_simplified_support(db, service_id, findings, selected_scan)
        expected = queries.group_simplified_findings(findings, selected_scan, {})
        rows, info = queries.page_simplified_findings(db, service_id, findings, selected_scan, {}, 2, 2)
        assert rows == expected[2:4]
        assert info['total_items'] == len(expected) == 4
    engine.dispose()


def test_large_group_keeps_every_cve_and_current_images_without_hydration(monkeypatch):
    from datetime import timedelta
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    now = utcnow()
    with Session(engine) as db:
        service = Service(service_key='large-group', name='Large group')
        db.add(service); db.flush()
        scan = Execution(service_id=service.id, execution_key='large-group',
                         scanned_at=now, complete=True, raw_payload={})
        db.add(scan); db.flush()
        findings = []
        due = {}
        for index in range(801):
            finding = Finding(service_id=service.id, cve=f'CVE-{index:04}', severity='High',
                              first_seen=now, episode_started=now, last_seen=now)
            db.add(finding); db.flush()
            for image in ('image-a', 'image-b'):
                db.add(FindingObservation(finding_id=finding.id, execution_id=scan.id,
                    image=image, package='shared', fixed_version='2',
                    evidence={'remediation': ['Upgrade', {'enabled': True}]}))
            findings.append(N(id=finding.id, cve=finding.cve, severity=finding.severity,
                              active=True, observations=[]))
            due[finding.id] = now + timedelta(days=index + 1)
        db.commit()
        scan_id, service_id = scan.id, service.id
        queries.load_simplified_support(db, service_id, findings, N(id=scan_id))
        expected = queries.group_simplified_findings(findings, N(id=scan_id), due)
        monkeypatch.setattr(queries, 'load_simplified_support',
                            lambda *args: (_ for _ in ()).throw(AssertionError('full evidence hydration')))
        rows, info = queries.page_simplified_findings(db, service_id, findings, N(id=scan_id), due, 1, 50)
        assert rows == expected
        assert len(rows[0]['cves']) == 801
        assert rows[0]['images'] == ['image-a', 'image-b']
        assert rows[0]['due'] == now + timedelta(days=1)
        assert info == {'page': 1, 'total_items': 1, 'total_pages': 1}
    engine.dispose()

def test_simplified_fast_candidates_match_canonical_risk_and_json(monkeypatch):
    from datetime import timedelta
    from app import main
    from app.models import ExceptionRecord
    from app.service_tab_queries import prepare_service_tab_view
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    now = utcnow()
    monkeypatch.setattr(main, 'kev_cves', lambda: set())
    monkeypatch.setattr(main, 'epss_scores', lambda: {})
    monkeypatch.setattr(main, 'risk_metadata', lambda cve: (False, 0))
    settings = dict(main.CONFIG_DEFAULTS, compliance_mode='risk_based', minimum_severity='High', kev_enabled='false', epss_enabled='false')
    with Session(engine) as db:
        service = Service(service_key='fast', name='Fast')
        db.add(service); db.flush()
        scan = Execution(service_id=service.id, execution_key='fast', scanned_at=now, complete=True, raw_payload={})
        db.add(scan); db.flush()
        for index, severity in enumerate(['High', 'Critical', 'Low', 'High', 'High']):
            finding = Finding(service_id=service.id, cve=f'CVE-{index}', severity=severity,
                active=index != 4, first_seen=now, episode_started=now-timedelta(days=100 if index == 3 else 1), last_seen=now)
            db.add(finding); db.flush()
            if index == 1:
                db.add(ExceptionRecord(finding_id=finding.id, justification='approved', approved_by='test',
                    starts_at=now-timedelta(days=1), expires_at=now+timedelta(days=1)))
            db.add(FindingObservation(finding_id=finding.id, execution_id=scan.id, image='image',
                package='Straße', fixed_version='2', evidence={'remediation': {'nested': [True, 1]}}))
        db.commit()
        legacy, proxy, latest = queries.prepare_findings_view(db, service, now, settings, main.service_view)
        expected, expected_page = queries.page_simplified_findings(db, service.id, legacy['active'], latest,
            legacy['due_dates'], 1, 50)
        candidates, keys, due, severities = queries.prepare_simplified_candidates(db, service, now, settings, latest)
        result, page = queries.page_simplified_findings(db, service.id, candidates, latest, due, 1, 50,
                                                     grouping_metadata=keys)
        assert result == expected
        assert page == expected_page
        assert [f.id for f in candidates] == [f.id for f in legacy['active']]
        assert set(severities) == {'High', 'Critical'}
        header, _, _ = prepare_service_tab_view(db, service, now, settings, main.service_view, header_only=True)
        for field in ('version', 'compliant', 'archive', 'last_execution', 'skipped_images', 'skipped_charts'):
            assert header[field] == legacy[field]
        import pytest
        from starlette.requests import Request
        monkeypatch.setattr(main, 'configuration_for_service', lambda *args: settings)
        monkeypatch.setattr(main, 'utcnow', lambda: now)
        monkeypatch.setattr(main, 'page_context', lambda auth, **kwargs: kwargs)
        monkeypatch.setattr(main.templates, 'TemplateResponse', lambda request, name, context: context)
        monkeypatch.setattr(queries, 'prepare_findings_view', lambda *args: pytest.fail('whole service finding preparation'))
        request = Request({'type': 'http', 'method': 'GET', 'path': '/', 'query_string': b'', 'headers': []})
        route = main.service_detail('fast', request, findings_view='simplified', severity=[], db=db, auth=N())
        summaries = route['simplified_findings']
        assert len(summaries) == len(expected)
        for summary, canonical in zip(summaries, expected):
            for key in ('package', 'remediation', 'fixed_version', 'severity', 'due'):
                assert summary[key] == canonical[key]
            assert summary['member_count'] == len(canonical['cves'])
            assert summary['representative_cve'] == canonical['cves'][0]
            assert summary['image_count'] == len(canonical['images'])
            assert not {'cves', 'images', 'finding_ids', 'severities', 'fixed_versions'}.intersection(summary)
        assert set(route['severity_options']) == {'High', 'Critical', 'Low'}
        assert route['total_items'] == expected_page['total_items']
    engine.dispose()
