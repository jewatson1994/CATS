"""Local service visibility for approved OCI pulls."""
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .auth import AuthContext, record_audit, require_permission, require_user
from .database import get_db
from .models import Service
from .oci_models import OCIServicePullAccess
from .service_oci import _csrf


router = APIRouter(prefix='/api/oci', tags=['OCI service access'])


def service_pull_is_public(db: Session, service_id: int) -> bool:
    # Scalar SQL bypasses the ORM identity map on every authorization check.
    # A missing service or setting never makes a pull public.
    return db.scalar(select(OCIServicePullAccess.public).join(Service,
        Service.id == OCIServicePullAccess.service_id).where(Service.id == service_id)) is True


def _service(db: Session, service_id: int):
    service = db.get(Service, service_id, populate_existing=True)
    if service is None:
        raise HTTPException(404, 'Service not found')
    return service


@router.get('/services/{service_id}/pull-access')
def get_pull_access(service_id: int, db: Session = Depends(get_db),
                    auth: AuthContext = Depends(require_user)):
    _service(db, service_id)
    if not auth.has('service.view', service_id):
        raise HTTPException(403, 'Service viewing permission required')
    return {'service_id': service_id, 'public': service_pull_is_public(db, service_id)}


@router.put('/services/{service_id}/pull-access')
async def set_pull_access(service_id: int, request: Request, db: Session = Depends(get_db),
                          auth: AuthContext = Depends(require_permission('release.destination.manage'))):
    if not auth.has('release.destination.manage'):
        raise HTTPException(403, 'Distribution management permission required')
    _csrf(request, auth)
    _service(db, service_id)
    try:
        data = await request.json()
    except ValueError:
        raise HTTPException(422, 'JSON object required') from None
    if not isinstance(data, dict) or set(data) != {'public'} or type(data['public']) is not bool:
        raise HTTPException(422, 'public must be a boolean')
    # Lock the service row to serialize concurrent first-time settings.
    db.execute(select(Service.id).where(Service.id == service_id).with_for_update())
    previous = service_pull_is_public(db, service_id)
    setting = db.get(OCIServicePullAccess, service_id, populate_existing=True)
    if setting is None:
        setting = OCIServicePullAccess(service_id=service_id)
        db.add(setting)
    setting.public = data['public']
    record_audit(db, auth, 'oci.service.pull_access', 'service', service_id,
                 previous_public=previous, public=setting.public)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, 'Service pull access changed concurrently. Retry the update.') from None
    return {'service_id': service_id, 'public': data['public']}
