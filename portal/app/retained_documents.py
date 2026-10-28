"""Bounded, byte-preserving scanner and SBOM evidence carried by an execution."""
import base64
import binascii
from hashlib import sha256
import os
import re
import zlib
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SBOM_FORMATS = ("syft-json", "cyclonedx-json", "cyclonedx-xml", "spdx-json")
SCANNER_FORMATS = ("grype-json", "trivy-json")


def evidence_limits():
    return (max(1, int(os.getenv("CATS_INGEST_MAX_EVIDENCE_BYTES", str(64 * 1024 * 1024)))),
            max(1, int(os.getenv("CATS_INGEST_MAX_EVIDENCE_ENCODED_BYTES", str(8 * 1024 * 1024)))),
            max(1, int(os.getenv("CATS_INGEST_MAX_EVIDENCE_FILES", "2048"))))


class DocumentIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid")
    category: Literal["scanner", "sbom"]
    format: Literal["grype-json", "trivy-json", "syft-json", "cyclonedx-json", "cyclonedx-xml", "spdx-json"]
    name: str = Field(min_length=1, max_length=240)
    image: str = Field(default="", max_length=1000)

    @field_validator("name")
    @classmethod
    def safe_name(cls, value):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", value) or value in {".", ".."}:
            raise ValueError("Unsafe retained evidence filename")
        return value

    @model_validator(mode="after")
    def matching_format(self):
        if self.format not in (SCANNER_FORMATS if self.category == "scanner" else SBOM_FORMATS):
            raise ValueError("Retained evidence category does not match format")
        return self


class EvidenceDocument(DocumentIdentity):
    encoding: Literal["gzip+base64"] = "gzip+base64"
    content: str
    bytes: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    # Interchange SBOMs are conversions of this exact original Syft document.
    derived_from_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    conversion_timestamp_source: Literal["source-file-mtime"] | None = None

    @model_validator(mode="after")
    def original_scanner_output(self):
        if self.category == "scanner" and (self.derived_from_sha256 is not None or self.conversion_timestamp_source):
            raise ValueError("Raw scanner evidence cannot be synthesized")
        return self


class UnavailableDocument(DocumentIdentity):
    reason: str = Field(min_length=1, max_length=300)


def decode_document(document, *, max_bytes=None):
    """Check size before decoding and stop decompression at the permitted bound."""
    limit, encoded_limit, _ = evidence_limits()
    limit = min(limit, max_bytes) if max_bytes is not None else limit
    if document.bytes > limit or len(document.content) > encoded_limit:
        raise ValueError("Retained evidence byte limit exceeded")
    try:
        compressed = base64.b64decode(document.content, validate=True)
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        raw = decoder.decompress(compressed, min(limit, document.bytes) + 1)
        if (len(raw) > limit or not decoder.eof or decoder.unused_data
                or len(raw) != document.bytes or sha256(raw).hexdigest() != document.sha256):
            raise ValueError("Retained evidence size or checksum mismatch")
    except (binascii.Error, zlib.error) as exc:
        raise ValueError("Invalid retained evidence encoding") from exc
    return raw


def validate_documents(documents, unavailable=()):
    limit, encoded_limit, count_limit = evidence_limits()
    if len(documents) + len(unavailable) > count_limit:
        raise ValueError("Retained evidence file limit exceeded")
    total = encoded = 0
    identities = set()
    for document in [*documents, *unavailable]:
        identity = (document.category, document.format, document.name.casefold())
        if identity in identities:
            raise ValueError("Duplicate retained evidence filename")
        identities.add(identity)
        if isinstance(document, EvidenceDocument):
            total += document.bytes
            encoded += len(document.content)
            if total > limit or encoded > encoded_limit:
                raise ValueError("Retained evidence byte limit exceeded")
            decode_document(document)
    return documents
