"""Preserve Canonical's explicit USN-to-CVE aliases without inventing relationships."""
import re

CVE = re.compile(r'CVE-\d{4}-\d{4,}')


def statement_cves(document, statement):
    vulnerability = statement['vulnerability']
    primary = vulnerability.get('name') or vulnerability.get('@id')
    if isinstance(primary, str) and CVE.fullmatch(primary):
        return [primary]
    # USNs group multiple fixed CVEs, unlike ordinary vulnerability aliases.
    # Restrict this adapter to Canonical's published USN schema and product scope.
    if not (isinstance(primary, str) and re.fullmatch(r'USN-\d+-\d+', primary)
            and document.get('author') == 'Canonical Ltd.'
            and str(document.get('@id', '')).startswith('https://github.com/canonical/ubuntu-security-notices/blob/main/vex/usn/')
            and vulnerability.get('@id') == 'https://ubuntu.com/security/notices/' + primary
            and statement.get('status') == 'fixed'):
        raise ValueError('Invalid CVE or unsupported advisory alias')
    aliases = vulnerability.get('aliases')
    if not isinstance(aliases, list) or len(aliases) > 1000 or any(not isinstance(a, str) for a in aliases):
        raise ValueError('Invalid bounded USN aliases')
    cves = sorted({a for a in aliases if CVE.fullmatch(a)})
    if not cves or any(a.startswith('CVE-') and not CVE.fullmatch(a) for a in aliases):
        raise ValueError('USN requires explicit valid CVE aliases')
    if any(not str(p.get('@id', '')).startswith('pkg:deb/ubuntu/') for p in statement['products']):
        raise ValueError('USN product outside Ubuntu scope')
    return cves
