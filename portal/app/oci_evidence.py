"""Deliver existing Cyber-signed bundles under live machine authorization."""
import hashlib
import os
from pathlib import Path
from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse
from starlette.background import BackgroundTask
from . import cyber_approvals as approvals

router = APIRouter()

@router.get('/api/oci/evidence/{repository:path}/manifests/{digest}/offline')
def offline(repository: str, digest: str, request: Request):
    from . import oci_proxy as proxy
    if not proxy.DIGEST.fullmatch(digest):
        raise proxy.Denied('Immutable manifest digest required', 400, 'DIGEST_INVALID')
    stream = None
    try:
        with proxy.SessionLocal() as db:
            mapping = proxy.mapping_for(db, repository)
            machine = proxy.principal(db, request, mapping.id)
            decision = proxy.require(db, mapping, digest)
            row = db.get(approvals.CyberApproval, decision.approval_id, populate_existing=True) if decision.approval_id else None
            receipt = row.publication or {} if row else {}
            if (not row or row.service_id != mapping.service_id or row.publish_status != 'published'
                or receipt.get('status') != 'published' or receipt.get('verification_status') != 'verified'
                or receipt.get('signature_status') != 'verified'):
                raise proxy.Denied('Verified Cyber evidence unavailable', 404, 'MANIFEST_UNKNOWN')
            manifest = receipt.get('manifest') or {}
            if manifest.get('approval_id') != row.id or manifest.get('snapshot_digest') != row.snapshot_digest:
                raise proxy.Denied('Evidence receipt does not match approval')
            if not receipt.get('bundle_path') or not proxy.DIGEST.fullmatch(str(receipt.get('bundle_digest', ''))):
                raise proxy.Denied('Verified Cyber evidence unavailable', 404, 'MANIFEST_UNKNOWN')
            # Same retained-path and checksum contract as the portal download route.
            path = Path(receipt['bundle_path']).resolve()
            if not path.is_relative_to((approvals.root() / row.release_key).resolve()) or not path.is_file():
                raise proxy.Denied('Retained evidence unavailable')
            stream = path.open('rb')
            checksum = 'sha256:' + hashlib.file_digest(stream, 'sha256').hexdigest()
            if checksum != receipt['bundle_digest']:
                raise proxy.Denied('Retained evidence integrity check failed')
            stream.seek(0)
            size = os.fstat(stream.fileno()).st_size
            approval_id = row.id
            db.commit()
            db.expire_all()
            mapping = proxy.mapping_for(db, repository)
            proxy.principal(db, request, mapping.id)
            current = proxy.require(db, mapping, digest)
            if current.approval_id != approval_id:
                raise proxy.Denied('Approval changed during evidence retrieval')
            proxy.audit(db, machine, mapping, digest, 'offline_evidence')
            db.commit()
        def chunks():
            try:
                while block := stream.read(1024 * 1024):
                    yield block
            finally:
                stream.close()
        return StreamingResponse(chunks(), media_type='application/zip', background=BackgroundTask(stream.close),
            headers={**proxy.V2, 'Content-Disposition':'attachment; filename="offline-bundle.zip"',
                'Content-Length':str(size), 'X-CATS-Approval-ID':str(approval_id), 'X-CATS-Evidence-Digest':checksum})
    except OSError:
        if stream:
            stream.close()
        raise proxy.Denied('Retained evidence unavailable') from None
    except BaseException:
        if stream:
            stream.close()
        raise
