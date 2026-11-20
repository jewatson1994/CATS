from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier

from sqlalchemy import select

from app import durable_jobs as jobs
from app.gitlab_topic_poll import KIND, PREVIEW_KIND
from app.topic_intake_models import GitLabTopicSource
from test_gitlab_topic_poll import source_db


def _another_source(db, source, namespace, origin=None):
    peer = GitLabTopicSource(name=namespace, origin=origin or source.origin, topic=source.topic,
        namespace=namespace, authorized_by_id=source.authorized_by_id, claim_group_id=source.claim_group_id,
        enabled=True)
    db.add(peer)
    db.flush()
    return peer.id


def test_simultaneous_workers_cannot_claim_two_mutating_polls_for_one_origin(source_db):
    sessions, source_id = source_db
    with sessions.begin() as db:
        peer_id = _another_source(db, db.get(GitLabTopicSource, source_id), "second-team")
        for identity in (source_id, peer_id):
            # Old persisted payloads have no origin key.
            jobs.submit(db, kind=KIND, payload={"source_id": identity}, commit=False)
    barrier = Barrier(2)
    def claim(worker):
        barrier.wait(timeout=5)
        return jobs.claim((KIND, PREVIEW_KIND), worker, sessions)
    with ThreadPoolExecutor(max_workers=2) as pool:
        owners = [row for row in pool.map(claim, ("worker-a", "worker-b")) if row]
    assert len(owners) == 1
    jobs.JobContext(owners[0], sessions).finish({})
    assert jobs.claim((KIND,), "worker-next", sessions).id != owners[0].id


def test_previews_and_other_origins_can_advance_while_a_poll_is_running(source_db):
    sessions, source_id = source_db
    with sessions.begin() as db:
        first = db.get(GitLabTopicSource, source_id)
        peer = _another_source(db, first, "second-team")
        remote = _another_source(db, first, "different-origin", "https://other.example")
        for kind, identity in ((KIND, source_id), (KIND, peer), (PREVIEW_KIND, peer), (KIND, remote)):
            jobs.submit(db, kind=kind, payload={"source_id": identity}, commit=False)
    kinds = (KIND, PREVIEW_KIND)
    running = jobs.claim(kinds, "one", sessions)
    assert jobs.claim(kinds, "two", sessions).kind == PREVIEW_KIND
    assert jobs.claim(kinds, "three", sessions).payload["source_id"] == remote
    assert jobs.claim(kinds, "four", sessions) is None
    with sessions.begin() as db:
        db.get(jobs.DurableJob, running.id).lease_until = jobs.now() - timedelta(seconds=1)
    successor = jobs.claim(kinds, "four", sessions)
    assert successor.payload["source_id"] == peer
    with sessions() as db:
        assert db.scalar(select(jobs.DurableJob.status).where(jobs.DurableJob.id == running.id)) == "queued"
