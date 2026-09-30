"""Positive, deployment-configurable exchange bounds."""
import os


def bound(name, default):
    value = int(os.getenv(name, str(default)))
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    return value


def workbook_bytes():
    return bound("CATS_WORKBOOK_MAX_BYTES", 20 * 1024 ** 2)


def bundle_bytes():
    return bound("CATS_BUNDLE_MAX_BYTES", 100 * 1024 ** 2)


def workbook_expanded_bytes():
    return bound("CATS_WORKBOOK_MAX_EXPANDED_BYTES", 100 * 1024 ** 2)


def workbook_members():
    return bound("CATS_WORKBOOK_MAX_MEMBERS", 2000)


def workbook_rows():
    return bound("CATS_WORKBOOK_MAX_ROWS", 10000)


def workbook_columns():
    return bound("CATS_WORKBOOK_MAX_COLUMNS", 100)
