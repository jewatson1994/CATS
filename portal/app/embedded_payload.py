"""Bounded ordered payload parts, authenticated by the signed manifest."""
import hashlib
import re

PART_BYTES = 64 * 1024 * 1024
READ_BYTES = 1024 * 1024


def payload_paths(directory, manifest):
    parts = manifest.get('payload_parts')
    if parts is None:
        return [directory / 'intelligence.jsonl.gz']
    if not isinstance(parts, list) or not 1 <= len(parts) <= 32:
        raise ValueError('Invalid payload part count')
    paths, total = [], 0
    for index, part in enumerate(parts):
        if (not isinstance(part, dict) or part.get('name') != f'intelligence.jsonl.gz.part{index:04d}'
                or type(part.get('bytes')) is not int or not 0 < part['bytes'] <= PART_BYTES
                or not re.fullmatch(r'[0-9a-f]{64}', str(part.get('sha256', '')))):
            raise ValueError('Invalid ordered payload part')
        path = directory / part['name']
        if path.stat().st_size != part['bytes']:
            raise ValueError('Payload part size mismatch')
        total += part['bytes']
        paths.append(path)
    if total != manifest['payload_bytes']:
        raise ValueError('Payload part total mismatch')
    return paths


class PayloadReader:
    def __init__(self, paths, manifest=None):
        paths = tuple(paths)
        if manifest is None:
            # Compatibility for callers inspecting a local payload. Production
            # verification and import always supply authenticated signed sizes.
            parts = [(path, path.stat().st_size, None) for path in paths]
        elif manifest.get('payload_parts') is None:
            if len(paths) != 1:
                raise ValueError('Invalid legacy payload path count')
            parts = [(paths[0], manifest['payload_bytes'], None)]
        else:
            metadata = manifest['payload_parts']
            if len(paths) != len(metadata):
                raise ValueError('Invalid payload part count')
            parts = [(path, part['bytes'], part['sha256'])
                     for path, part in zip(paths, metadata)]
        if any(type(size) is not int or size < 0 for _, size, _ in parts):
            raise ValueError('Invalid payload byte bound')
        if manifest is not None and sum(size for _, size, _ in parts) != manifest['payload_bytes']:
            raise ValueError('Payload part total mismatch')
        self.parts, self.stream = iter(parts), None
        self.remaining, self.digest, self.expected_digest = 0, None, None

    def _finish_part(self):
        # A stat can race with replacement or growth. Read at most one unsigned
        # byte to establish EOF, and never pass that sentinel to gzip or hashes.
        if self.stream.read(1):
            raise ValueError('Payload changed: part exceeds signed size')
        if self.expected_digest is not None and self.digest.hexdigest() != self.expected_digest:
            raise ValueError('Payload changed: part digest mismatch')
        self.stream.close()
        self.stream = None

    def read(self, size):
        if size < 0:
            raise ValueError('Unbounded compressed payload read')
        if size == 0:
            return b''
        chunks = []
        requested = min(size, READ_BYTES)
        while requested:
            if self.stream is None:
                part = next(self.parts, None)
                if part is None:
                    break
                path, self.remaining, self.expected_digest = part
                self.stream = path.open('rb')
                self.digest = hashlib.sha256() if self.expected_digest is not None else None
            if self.remaining == 0:
                self._finish_part()
                continue
            count = min(requested, self.remaining)
            block = self.stream.read(count)
            if not block:
                raise ValueError('Payload changed: part is shorter than signed size')
            if len(block) > count:
                raise ValueError('Payload changed: part exceeds requested byte bound')
            if self.digest is not None:
                self.digest.update(block)
            self.remaining -= len(block)
            requested -= len(block)
            chunks.append(block)
            if self.remaining == 0:
                self._finish_part()
        return b''.join(chunks)

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        if self.stream is not None:
            self.stream.close()
