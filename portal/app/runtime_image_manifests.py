"""Distinguish a single scanned platform manifest from an OCI index at release boundaries."""
import base64
import hashlib
import json

from sqlalchemy import or_, select

from .artifact_catalog import GlobalArtifact, ServiceArtifactAssignment
from .oci_models import OCIManifest, OCIRepository
from .retained_documents import EvidenceDocument, decode_document


INDEX_TYPES = ('application/vnd.oci.image.index.v1+json', 'application/vnd.docker.distribution.manifest.list.v2+json')
IMAGE_TYPES = ('application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.v2+json')
INDEX_BLOCKER = 'An image index requires independent assessment of its platform manifests. Pin the reviewed platform manifest.'


def runtime_manifest_issue(document, media):
    if media in INDEX_TYPES or 'manifests' in document:
        return INDEX_BLOCKER
    config = document.get('config')
    if (media not in IMAGE_TYPES or document.get('schemaVersion') != 2 or document.get('artifactType')
            or not isinstance(config, dict) or config.get('mediaType') not in (
                'application/vnd.oci.image.config.v1+json', 'application/vnd.docker.container.image.v1+json')
            or not isinstance(document.get('layers'), list)):
        return 'The runtime release requires a platform image manifest with a container image configuration.'
    return None


def check_scanned_platform(raw, digest):
    different = 'The scanner assessed a different platform manifest from the requested image digest.'
    overview = raw.get('service_overview') or {}
    for image in overview.get('images') or overview.get('container_images') or []:
        if isinstance(image, dict) and (image.get('media_type') or image.get('mediaType')) in INDEX_TYPES:
            raise ValueError(INDEX_BLOCKER)
    for component in raw.get('sbom_components') or []:
        if component.get('image_manifest_digest') and component['image_manifest_digest'] != digest:
            raise ValueError(different)
    for item in raw.get('evidence_documents') or []:
        if item.get('format') != 'syft-json':
            continue
        document = json.loads(decode_document(EvidenceDocument.model_validate(item)))
        source = document.get('source') if isinstance(document, dict) else None
        if not isinstance(source, dict) or source.get('type') != 'image':
            continue
        for metadata in (source.get('metadata'), source.get('target')):
            if not isinstance(metadata, dict):
                continue
            if metadata.get('mediaType') in INDEX_TYPES:
                raise ValueError(INDEX_BLOCKER)
            if metadata.get('manifestDigest') and metadata['manifestDigest'] != digest:
                raise ValueError(different)
            if metadata.get('manifest'):
                if not isinstance(metadata['manifest'], str):
                    raise ValueError('Invalid native scanner image manifest.')
                content = base64.b64decode(metadata['manifest'], validate=True)
                if 'sha256:' + hashlib.sha256(content).hexdigest() != digest:
                    raise ValueError(different)
                manifest = json.loads(content)
                if not isinstance(manifest, dict) or 'manifests' in manifest or manifest.get('mediaType') in INDEX_TYPES:
                    raise ValueError(INDEX_BLOCKER)


def known_index_digests(db, service_id, inventory):
    digests = {asset['digest'] for asset in inventory['images']}
    if not digests:
        return set()
    result = {proof['digest'] for proof in inventory.get('registry_resolutions', {}).values()
              if proof.get('media_type') in INDEX_TYPES}
    result.update(db.scalars(select(GlobalArtifact.digest).join(
        ServiceArtifactAssignment, ServiceArtifactAssignment.artifact_id == GlobalArtifact.id
    ).where(ServiceArtifactAssignment.service_id == service_id, GlobalArtifact.digest.in_(digests),
            GlobalArtifact.media_type.in_(INDEX_TYPES))))
    cached = db.execute(select(OCIManifest.digest, OCIManifest.media_type, OCIManifest.content).join(OCIRepository).where(
        OCIRepository.service_id == service_id, OCIManifest.digest.in_(digests),
        or_(OCIManifest.media_type.in_(INDEX_TYPES), OCIManifest.content.contains('"manifests"'))))
    for digest, media, content in cached:
        if 'sha256:' + hashlib.sha256(content.encode()).hexdigest() == digest:
            if media in INDEX_TYPES or 'manifests' in json.loads(content):
                result.add(digest)
    return result
