from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.database import Base
from app.models import RemediationExecution
from app.remediation_retention import RetentionPolicy, cleanup_remediation_artifacts, retention_policy


@pytest.fixture
def db():
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


def candidate(db,root,key,age=1,size=10,status='completed',delivery='failed'):
    folder = root / key
    folder.mkdir()
    artifact = folder / 'candidate.zip'
    artifact.write_bytes(b'x'*size)
    row = RemediationExecution(job_key=key,service_id=1,requested_by_id=1,status=status,delivery_status=delivery,
        artifact_path=str(artifact),artifact_digest='sha256:'+'a'*64,
        created_at=datetime.now(timezone.utc)-timedelta(days=age))
    db.add(row)
    db.flush()
    return row


def test_failed_delivery_retained_for_retry_then_expires(db,tmp_path):
    row = candidate(db,tmp_path,'R1',age=5)
    result = cleanup_remediation_artifacts(db,tmp_path,policy=RetentionPolicy(30,7,100))
    assert result['removed'] == [] and Path(row.artifact_path).exists()
    result = cleanup_remediation_artifacts(db,tmp_path,now=datetime.now(timezone.utc)+timedelta(days=31),policy=RetentionPolicy(30,7,100))
    assert result['removed'] == ['R1'] and row.artifact_path is None
    assert row.artifact_digest == 'sha256:'+'a'*64 and row.delivery_status == 'failed'


def test_quota_prefers_published_over_undelivered(db,tmp_path):
    failed = candidate(db,tmp_path,'R1',age=5,size=20)
    published = candidate(db,tmp_path,'R2',age=1,size=20,delivery='published')
    result = cleanup_remediation_artifacts(db,tmp_path,policy=RetentionPolicy(30,7,25))
    assert result['removed'] == ['R2']
    assert published.artifact_path is None and Path(failed.artifact_path).exists()
    assert result['retained_bytes'] == 20 and not result['over_quota']


@pytest.mark.parametrize('status,delivery', [('queued','failed'),('running','failed'),('completed','running')])
def test_active_work_never_removed_and_overquota_reported(db,tmp_path,status,delivery):
    row = candidate(db,tmp_path,'ACTIVE',age=100,size=20,status=status,delivery=delivery)
    result = cleanup_remediation_artifacts(db,tmp_path,policy=RetentionPolicy(30,7,10))
    assert result['over_quota'] and not result['removed'] and Path(row.artifact_path).exists()


def test_download_only_retention_bounded_by_quota(db,tmp_path):
    old = candidate(db,tmp_path,'OLD',age=5,size=20,delivery='download_ready')
    new = candidate(db,tmp_path,'NEW',age=1,size=20,delivery='download_ready')
    result = cleanup_remediation_artifacts(db,tmp_path,policy=RetentionPolicy(30,7,25))
    assert result['removed'] == ['OLD'] and old.artifact_path is None
    assert Path(new.artifact_path).exists()


def test_no_traversal_or_external_artifact_path_deletion(db,tmp_path):
    outside = tmp_path.parent/'outside-content.txt'
    outside.write_text('preserve')
    row = RemediationExecution(job_key='../escape',service_id=1,requested_by_id=1,status='completed',artifact_path=str(outside),created_at=datetime.now(timezone.utc)-timedelta(days=100))
    db.add(row)
    db.flush()
    result = cleanup_remediation_artifacts(db,tmp_path,policy=RetentionPolicy(1,1,1))
    assert result['skipped'] == ['../escape'] and outside.read_text() == 'preserve'


def test_nested_files_cleaned_only_under_known_candidate(db,tmp_path):
    candidate(db,tmp_path,'EXPIRED',age=40)
    nested = tmp_path/'EXPIRED'/'helm'
    nested.mkdir()
    (nested/'chart.tgz').write_bytes(b'chart')
    unknown = tmp_path/'untracked'
    unknown.mkdir()
    (unknown/'preserve').write_text('keep')
    result = cleanup_remediation_artifacts(db,tmp_path,policy=RetentionPolicy(30,7,100))
    assert result['removed'] == ['EXPIRED'] and not (tmp_path/'EXPIRED').exists()
    assert (unknown/'preserve').exists()


def test_policy_is_bounded_and_configurable(monkeypatch):
    monkeypatch.setenv('CATS_REMEDIATION_RETENTION_DAYS','10')
    monkeypatch.setenv('CATS_REMEDIATION_RETENTION_MAX_BYTES','1000')
    assert retention_policy() == RetentionPolicy(10,7,1000)
    with pytest.raises(ValueError):
        RetentionPolicy(0,0,0)


def test_unknown_content_counts_toward_quota_without_deletion(db,tmp_path):
    orphan = tmp_path/'untracked'
    orphan.mkdir()
    (orphan/'preserve').write_bytes(b'x'*20)
    result = cleanup_remediation_artifacts(db,tmp_path,policy=RetentionPolicy(30,7,10))
    assert result['over_quota'] and result['retained_bytes'] == 20
    assert not result['removed'] and (orphan/'preserve').exists()


def test_linked_content_is_never_followed(db,tmp_path):
    candidate(db,tmp_path,'LINKED',age=40)
    external = tmp_path.parent/'outside-secret.txt'
    external.write_text('keep')
    try:
        (tmp_path/'LINKED'/'link').symlink_to(external)
    except OSError:
        pytest.skip('OS does not permit symlink creation')
    result = cleanup_remediation_artifacts(db,tmp_path,policy=RetentionPolicy(30,7,1))
    assert result['removed'] == [] and result['skipped'] == ['LINKED']
    assert external.read_text() == 'keep'
