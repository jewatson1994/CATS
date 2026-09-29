"""Offline, bounded semantic validation for typed spreadsheet fields."""
from ipaddress import ip_address
import re
from urllib.parse import urlsplit


def hostname(value):
    """Validate DNS syntax without resolving or contacting the supplied host."""
    if not isinstance(value, str) or len(value) > 254:
        return False
    try:
        encoded = value.rstrip(".").encode("idna").decode("ascii")
    except UnicodeError:
        return False
    return len(encoded) <= 253 and "." in encoded and all(
        re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
        for label in encoded.split("."))


def validate_values(values):
    """Normalize explicit booleans/severity; return field-specific errors."""
    errors = []
    for key, value in list(values.items()):
        if value is None or value == "":
            continue
        # Parser reports oversized cells separately; never parse unbounded input.
        if len(str(value)) > 8000:
            continue
        if key in {"asset.ip", "asset.public_ip"}:
            try:
                if not isinstance(value, str):
                    raise ValueError()
                ip_address(value.strip())
            except ValueError:
                errors.append(f"{key}: expected an IPv4 or IPv6 address")
        elif key in {"asset.fqdn", "network.fqdn"}:
            if not hostname(str(value).strip()):
                errors.append(f"{key}: expected a fully qualified DNS name")
        elif key == "asset.public_url":
            urls = re.split(r"[\s;,]+", str(value).strip())
            valid = len(urls) <= 32
            for url in urls[:32]:
                try:
                    parsed = urlsplit(url)
                    host = parsed.hostname
                    if parsed.scheme.lower() not in {"http", "https"} or not host or parsed.username is not None or parsed.password is not None or "\\" in url:
                        raise ValueError()
                    if parsed.port is not None and not 1 <= parsed.port <= 65535:
                        raise ValueError()
                    try:
                        ip_address(host)
                    except ValueError:
                        if not hostname(host):
                            raise ValueError()
                except ValueError:
                    valid = False
            if not valid:
                errors.append(f"{key}: expected up to 32 HTTP(S) URLs without credentials")
        elif key in {"asset.public_facing", "asset.virtual", "asset.critical_information"}:
            normalized = str(value).strip().lower()
            if normalized in {"true", "yes", "1", "1.0"}:
                values[key] = True
            elif normalized in {"false", "no", "0", "0.0"}:
                values[key] = False
            else:
                errors.append(f"{key}: expected yes/no, true/false, or 1/0")
        elif key in {"finding.severity", "finding.raw_severity", "finding.residual_risk"}:
            normalized = str(value).strip().lower()
            allowed = {name.lower(): name for name in ("Critical", "High", "Medium", "Low", "Negligible", "Informational", "Unknown")}
            allowed.update({"moderate": "Medium", "info": "Informational", "none": "Negligible"})
            if normalized in allowed:
                values[key] = allowed[normalized]
            else:
                errors.append(f"{key}: expected Critical, High, Medium, Low, Negligible, Informational, or Unknown")
    return errors
