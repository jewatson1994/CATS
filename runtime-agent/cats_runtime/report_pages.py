"""Deliver one durable inventory, using pages when it outgrows a single request."""
import hashlib
import json


MAX_WORKLOADS = 20000
MAX_REPORT_BYTES = 16 * 1024 * 1024
_SINGLE_ROWS = 2000
_SINGLE_BYTES = 2 * 1024 * 1024
_PAGE_ROWS = 512
_PAGE_BYTES = 1024 * 1024


def send_report(client, token, report):
    from .agent import AgentError, encode_json

    observations = report["workloads"]
    if len(observations) <= _SINGLE_ROWS and len(encode_json(report)) <= _SINGLE_BYTES:
        return client.request("POST", "/api/runtime/reports", report, token)

    meta = {key: value for key, value in report.items() if key != "workloads"}
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    fingerprint = hashlib.sha256(canonical.encode()).hexdigest()
    pages, page, size = [], [], 0
    for item in observations:
        length = len(encode_json(item)) + 1
        if page and (len(page) >= _PAGE_ROWS or size + length > _PAGE_BYTES):
            pages.append(page)
            page, size = [], 0
        page.append(item)
        size += length
    if page:
        pages.append(page)
    for index, page in enumerate(pages):
        envelope = {**meta, "workloads": page, "page": index, "pages": len(pages),
                    "snapshot_sha256": fingerprint}
        ack = client.request("POST", "/api/runtime/reports/pages", envelope, token)
        if not isinstance(ack, dict) or ack.get("sequence") != report["sequence"]:
            raise AgentError("invalid_report_ack")
        if ack.get("accepted") is True:
            # Retrying after a lost final ACK may complete on the first page.
            return ack
        if ack.get("received") is not True or ack.get("page") != index:
            raise AgentError("invalid_report_ack")
    raise AgentError("invalid_report_ack")
