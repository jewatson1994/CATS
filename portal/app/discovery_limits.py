"""Operator-selected Discovery budgets; zero disables each size/count budget."""
import os


def limit(name):
    value = int(os.getenv('CATS_DISCOVERY_MAX_' + name, '0'))
    if value < 0:
        raise ValueError('Discovery limits must be non-negative')
    return value


def staging_limits():
    return dict(max_file=limit('FILE_BYTES'), max_total=limit('EXTRACTED_BYTES'), max_files=limit('FILES'),
                max_archive_bytes=limit('UPLOAD_BYTES'))
