"""Project-scoped CI admission and receipts for the existing scanner queue."""
import errno
import hashlib
import json
import re
import secrets
import shutil
from typing import Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import ForeignKey, String, UniqueConstraint, delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, Session, mapped_column
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import UploadFile
from starlette.formparsers import MultiPartException, MultiPartParser

from .database import Base, get_db
from .helm_archives import compressed_limit, limit
from .models import Execution, ServiceVersion
from .pipeline_api import PipelineError, project_bearer
from .project_credentials import authenticate_project, audit_project_use
from .scan_coordination import ScanJob, TERMINAL


class ProjectArtifactSubmission(Base):
    __tablename__ = 'project_artifact_submissions'
    __table_args__ = (UniqueConstraint('credential_id', 'client_key', name='uq_project_artifact_submission_key'),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey('services.id', ondelete='CASCADE'), index=True)
    credential_id: Mapped[int] = mapped_column(ForeignKey('project_credentials.id', ondelete='CASCADE'), index=True)
    client_key: Mapped[str] = mapped_column(String(128))
    request_digest: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(32))


ArtifactKind = Literal['auto', 'image', 'docker-archive', 'helm-chart', 'compose']


class ReferenceInput(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    kind: ArtifactKind = 'auto'
    reference: str = Field(min_length=1, max_length=512, description='An image reference or an oci:// Helm chart locator')
    version: str | None = Field(default=None, min_length=1, max_length=120)


class UploadOptions(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    kind: ArtifactKind = 'auto'
    version: str | None = Field(default=None, min_length=1, max_length=120)


class ArtifactSubmissionReceipt(BaseModel):
    id: str
    job_id: str
    status_url: str
    service_id: int
    service_key: str
    kind: str
    scan_status: str
    ingest_status: Literal['pending', 'ingesting', 'ingested', 'failed', 'expired']
    execution_id: int | None
    duplicate: bool


router = APIRouter(prefix='/api/v1/artifact-submissions', tags=['Project artifact submissions'],
    responses={code: {'model': PipelineError, 'description': description} for code, description in {
        400: 'Malformed multipart request or Content-Length', 401: 'Invalid project bearer',
        403: 'Insufficient project scope or inactive service', 404: 'Unknown submission for this project',
        409: 'Conflicting idempotency key or service state', 413: 'Upload exceeds configured size',
        415: 'Unsupported media type', 422: 'Invalid or ambiguous artifact input', 429: 'Scan queue is full',
        507: 'Insufficient scan staging capacity',
    }.items()})


class _BodyTooLarge(MultiPartException):
    pass


class _UploadParser(MultiPartParser):
    # Bound multipart headers independently from the potentially multi-GB file.
    header_bytes = 0

    def _count_header(self, size):
        self.header_bytes += size
        if self.header_bytes > 16384:
            raise _BodyTooLarge('Multipart headers exceed the limit')

    def on_header_field(self, data, start, end):
        self._count_header(end - start)
        super().on_header_field(data, start, end)

    def on_header_value(self, data, start, end):
        self._count_header(end - start)
        super().on_header_value(data, start, end)

    complete = False

    def on_end(self):
        self.complete = True


async def _chunks(request, maximum):
    length = request.headers.get('content-length')
    if length is not None:
        if not length.isascii() or not length.isdecimal() or len(length) > 20:
            raise HTTPException(400, 'Invalid Content-Length')
        if int(length) > maximum:
            raise _BodyTooLarge('Artifact request exceeds the configured byte limit')
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > maximum:
            raise _BodyTooLarge('Artifact request exceeds the configured byte limit')
        yield chunk


def _file_limit():
    return max(limit('CATS_PUBLIC_MAX_IMAGE_ARCHIVE_BYTES', 2 * 1024**3), compressed_limit())


def _input_error():
    return HTTPException(422, 'Provide an image or OCI chart reference as JSON, or one multipart file. Optional fields are kind and version.')


async def _read_input(request):
    media = request.headers.get('content-type', '').partition(';')[0].strip().lower()
    if media == 'application/json':
        try:
            raw = bytearray()
            async for chunk in _chunks(request, 16384):
                raw.extend(chunk)
            return ReferenceInput.model_validate_json(raw), None, None
        except _BodyTooLarge as exc:
            raise HTTPException(413, exc.message) from None
        except ValidationError:
            raise _input_error() from None
    if media != 'multipart/form-data':
        raise HTTPException(415, 'Use application/json or multipart/form-data')
    maximum = _file_limit()
    parser = _UploadParser(request.headers, _chunks(request, maximum + 65536),
                           max_files=1, max_fields=2, max_part_size=4096)
    try:
        form = await parser.parse()
        if not parser.complete:
            raise HTTPException(400, 'Incomplete multipart request')
        fields = form.multi_items()
        upload = form.get('file')
        if (len(form) != len(fields) or not isinstance(upload, UploadFile) or not upload.filename
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+ ()-]{0,199}', upload.filename)):
            raise _input_error()
        options = UploadOptions.model_validate({key: value for key, value in fields if key != 'file'})
        if not upload.size:
            raise HTTPException(422, 'The uploaded artifact is empty')
        if upload.size > maximum:
            raise _BodyTooLarge('Artifact file exceeds the configured byte limit')
        return options, upload, form
    except BaseException as exc:
        # Starlette closes failed parts for MultiPartException. Disconnects,
        # validation failures and parser errors also need deterministic cleanup.
        for stream in parser._files_to_close_on_error:
            stream.close()
        if isinstance(exc, _BodyTooLarge):
            raise HTTPException(413, exc.message) from None
        if isinstance(exc, MultiPartException):
            raise HTTPException(400, 'Invalid multipart fields or file count') from None
        if isinstance(exc, (ValueError, UnicodeError)):
            raise _input_error() from None
        raise


def _receipt(db, row, service_key, *, duplicate=False):
    job = db.get(ScanJob, row.id, populate_existing=True)
    execution_id = None
    if (job is not None and job.status in {'complete', 'incomplete'} and job.service_key == service_key
            and job.payload.get('project_credential_id') == row.credential_id
            and job.payload.get('ingest_service_db_id') == row.service_id and job.payload.get('ingested') is True
            and type(job.payload.get('pipeline_execution_id')) is int):
        execution_id = db.scalar(select(Execution.id).join(ServiceVersion, ServiceVersion.id == Execution.service_version_id)
            .where(Execution.id == job.payload['pipeline_execution_id'], Execution.execution_key == 'public:' + row.id,
                   Execution.service_id == row.service_id, Execution.scan_scope == 'evidence',
                   ServiceVersion.service_id == row.service_id, ServiceVersion.version == job.service_version))
    scan_status = job.status if job is not None else 'expired'
    if execution_id is not None:
        ingest_status = 'ingested'
    elif job is None:
        ingest_status = 'expired'
    elif job.status in TERMINAL:
        ingest_status = 'failed'
    elif job.payload.get('phase') == 'ingest':
        ingest_status = 'ingesting'
    else:
        ingest_status = 'pending'
    return ArtifactSubmissionReceipt(id=row.id, job_id=row.id, status_url='/api/v1/artifact-submissions/' + row.id,
        service_id=row.service_id, service_key=service_key, kind=row.kind, scan_status=scan_status,
        ingest_status=ingest_status, execution_id=execution_id, duplicate=duplicate)


def _queue(db, authorization, key, options, upload):
    from .main import PUBLIC_JOB_ROOT
    from .pipeline_scan_dispatch import prepare_scan
    job_id = secrets.token_hex(16)
    work_dir = PUBLIC_JOB_ROOT / job_id
    created = False
    retain_workspace = False
    try:
        filename = upload.filename if upload is not None else None
        file_hash = None
        if upload is not None:
            digest = hashlib.sha256()
            for chunk in iter(lambda: upload.file.read(1024 * 1024), b''):
                digest.update(chunk)
            file_hash = digest.hexdigest()
            upload.file.seek(0)
        parameters = options.model_dump()
        digest = hashlib.sha256(json.dumps([parameters, filename, file_hash], separators=(',', ':'),
                                           sort_keys=True).encode()).hexdigest()
        # Permissions and service identity may change while a large upload streams.
        project = authenticate_project(db, authorization, scope='artifacts.submit')
        service = project.service
        duplicate_query = select(ProjectArtifactSubmission).where(
            ProjectArtifactSubmission.credential_id == project.id, ProjectArtifactSubmission.client_key == key)
        existing = db.scalar(duplicate_query)
        if existing is None:
            row = ProjectArtifactSubmission(id=job_id, service_id=service.id, credential_id=project.id,
                                            client_key=key, request_digest=digest, kind=options.kind)
            db.add(row)
            try:
                db.flush()
            except IntegrityError:
                # A concurrent identical key may have committed after the first read.
                db.rollback()
                project = authenticate_project(db, authorization, scope='artifacts.submit')
                service = project.service
                existing = db.scalar(duplicate_query)
                if existing is None:
                    raise
        if existing is not None:
            if existing.request_digest != digest:
                raise HTTPException(409, 'Idempotency-Key already identifies different artifact input')
            return _receipt(db, existing, service.service_key, duplicate=True)
        work_dir.mkdir(parents=True, exist_ok=False)
        created = True
        if upload is not None:
            if shutil.disk_usage(work_dir).free < upload.size + 64 * 1024**2:
                raise HTTPException(507, 'Insufficient scan staging capacity')
            with (work_dir / 'submission-input').open('xb') as output:
                shutil.copyfileobj(upload.file, output, length=1024 * 1024)
        job = prepare_scan(db, service, job_id, work_dir, kind=options.kind,
            reference=getattr(options, 'reference', None), version=options.version, filename=filename, values=None)
        if project.owning_group_id is None or job.payload.get('pipeline_owning_group_id') != project.owning_group_id:
            raise HTTPException(403, 'The project credential no longer matches the service owning group')
        job.payload = {**job.payload, 'project_credential_id': project.id}
        if file_hash and (work_dir / 'retained-chart.tgz').is_file():
            job.payload = {**job.payload, 'chart_archive_digest': 'sha256:' + file_hash}
        row.kind = job.payload['pipeline_input_kind']
        audit_project_use(db, project, 'artifact.submitted', target_type='scan_job', target_id=job_id)
        db.flush()  # Production sessions disable autoflush; the receipt reads the persisted job.
        result = _receipt(db, row, service.service_key)
        # A lost database response may follow a successful commit. Keep staged
        # bytes in that case; the standard reaper handles uncommitted orphans.
        retain_workspace = True
        db.commit()
        return result
    finally:
        if not retain_workspace:
            db.rollback()
            if created:
                shutil.rmtree(work_dir, ignore_errors=True)


_UPLOAD_SCHEMA = UploadOptions.model_json_schema()
_UPLOAD_SCHEMA['properties']['file'] = {'type': 'string', 'format': 'binary'}
_UPLOAD_SCHEMA['required'] = ['file']


@router.post('', response_model=ArtifactSubmissionReceipt, status_code=202,
    responses={200: {'model': ArtifactSubmissionReceipt, 'description': 'Replay of a committed submission'}},
    openapi_extra={'x-required-project-scopes': ['artifacts.submit'], 'requestBody': {'required': True, 'content': {
        'application/json': {'schema': ReferenceInput.model_json_schema()},
        'multipart/form-data': {'schema': _UPLOAD_SCHEMA},
    }}})
async def submit(request: Request, response: Response,
                 idempotency_key: str = Header(alias='Idempotency-Key', min_length=1, max_length=128,
                                                pattern=r'^[A-Za-z0-9][A-Za-z0-9._:-]*$'),
                 bearer: HTTPAuthorizationCredentials | None = Depends(project_bearer), db: Session = Depends(get_db)):
    """Submit one artifact for scanning and ingestion into the credential's service."""
    authorization = request.headers.get('authorization', '')
    authenticate_project(db, authorization, scope='artifacts.submit')
    db.rollback()  # Release the connection while receiving and hashing the artifact.
    if len(request.headers.getlist('idempotency-key')) != 1:
        raise HTTPException(422, 'Provide exactly one Idempotency-Key header')
    form = None
    try:
        options, upload, form = await _read_input(request)
        result = await run_in_threadpool(_queue, db, authorization, idempotency_key, options, upload)
    except OSError as exc:
        if exc.errno in {errno.ENOSPC, getattr(errno, 'EDQUOT', -1)} or getattr(exc, 'winerror', None) == 112:
            raise HTTPException(507, 'Insufficient scan staging capacity') from None
        raise
    finally:
        if form is not None:
            await form.close()
    response.headers.update({'Cache-Control': 'private, no-store', 'Location': result.status_url})
    response.status_code = 200 if result.duplicate else 202
    return result


@router.get('/{submission_id}', response_model=ArtifactSubmissionReceipt,
            openapi_extra={'x-required-project-scopes': ['artifacts.submit']})
def submission_status(submission_id: str, request: Request, response: Response,
                      bearer: HTTPAuthorizationCredentials | None = Depends(project_bearer), db: Session = Depends(get_db)):
    """Read the durable scan and evidence-ingestion status using the submitting project credential."""
    project = authenticate_project(db, request.headers.get('authorization', ''), scope='artifacts.submit')
    row = db.scalar(select(ProjectArtifactSubmission).where(ProjectArtifactSubmission.id == submission_id,
        ProjectArtifactSubmission.service_id == project.service_id, ProjectArtifactSubmission.credential_id == project.id))
    if row is None:
        raise HTTPException(404, 'Artifact submission not found')
    response.headers['Cache-Control'] = 'private, no-store'
    return _receipt(db, row, project.service.service_key)


def clear_service_submissions(db, service_id):
    jobs = select(ProjectArtifactSubmission.id).where(ProjectArtifactSubmission.service_id == service_id)
    if db.scalar(select(ScanJob.id).where(ScanJob.id.in_(jobs), ScanJob.status.not_in(TERMINAL)).limit(1)):
        raise HTTPException(409, 'Wait for active project artifact scans to finish before deleting this service')
    db.execute(delete(ProjectArtifactSubmission).where(ProjectArtifactSubmission.service_id == service_id))
