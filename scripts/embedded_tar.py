"""Bound metadata that tarfile consumes before returning ordinary members.

Release archives may use PAX paths/global attributes and GNU long names/links.
Each extension is limited to 1 MiB, all padded extensions plus their headers to
64 MiB per archive, and consecutive extensions to 32. Applied PAX dictionaries
are limited to 256 fields. Sparse files are not supported for JSON feeds.
Ordinary member count and payload byte limits remain the caller's responsibility.
"""
import tarfile

MAX_EXTENSION_BYTES = 1024 * 1024
MAX_METADATA_BYTES = 64 * 1024 * 1024
MAX_EXTENSION_DEPTH = 32
MAX_PAX_FIELDS = 256
EXTENSIONS = frozenset((tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE,
                       tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK))


class BoundedTarInfo(tarfile.TarInfo):
    def _proc_member(self, archive):
        # This hook runs before the stdlib reads any extension body, including
        # recursive PAX/GNU headers that are hidden from archive iteration.
        if self.size < 0:
            raise ValueError('Negative tar member size')
        if self.type == tarfile.GNUTYPE_SPARSE:
            raise ValueError('Sparse tar members are unsupported')
        if self.type not in EXTENSIONS:
            return super()._proc_member(archive)
        if self.size > MAX_EXTENSION_BYTES:
            raise ValueError('Tar metadata extension exceeds byte bound')
        total = getattr(archive, '_bounded_metadata_bytes', 0) + 512 + self._block(self.size)
        if total > MAX_METADATA_BYTES:
            raise ValueError('Tar metadata exceeds aggregate byte bound')
        depth = getattr(archive, '_bounded_metadata_depth', 0) + 1
        if depth > MAX_EXTENSION_DEPTH:
            raise ValueError('Tar metadata exceeds extension depth bound')
        archive._bounded_metadata_bytes = total
        archive._bounded_metadata_depth = depth
        try:
            return super()._proc_member(archive)
        finally:
            archive._bounded_metadata_depth = depth - 1

    def _apply_pax_info(self, pax_headers, encoding, errors):
        # Global headers persist across members. Limit dictionary growth as well
        # as serialized bytes, before tarfile copies it onto every member.
        if len(pax_headers) > MAX_PAX_FIELDS:
            raise ValueError('Tar PAX metadata exceeds field bound')
        if any(key.startswith('GNU.sparse.') for key in pax_headers):
            raise ValueError('Sparse tar members are unsupported')
        super()._apply_pax_info(pax_headers, encoding, errors)
        if self.size < 0:
            raise ValueError('Negative tar member size')

    def _reject_sparse(self, *args):
        raise ValueError('Sparse tar members are unsupported')

    _proc_gnusparse_00 = _reject_sparse
    _proc_gnusparse_01 = _reject_sparse
    _proc_gnusparse_10 = _reject_sparse


def bounded_tar_open(name=None, mode='r|', *, fileobj=None):
    if mode not in ('r|', 'r|gz', 'r|xz'):
        raise ValueError('A supported streaming tar read mode is required')
    return tarfile.open(name=name, mode=mode, fileobj=fileobj, tarinfo=BoundedTarInfo)
