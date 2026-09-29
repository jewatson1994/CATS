from app.watchlist import component_matches, parse_entries, version_matches


def test_import_formats_and_comments():
    assert parse_entries("# ignored\n\nopenssl\npkg:pypi/requests\n", "txt") == [
        {"purl": "", "ecosystem": "", "name": "openssl", "version_constraint": ""},
        {"purl": "pkg:pypi/requests", "ecosystem": "", "name": "", "version_constraint": ""}]
    csv_rows = parse_entries("purl,ecosystem,name,version_constraint\n,python,requests,>=2.30\n", "csv")
    yaml_rows = parse_entries("entries:\n  - ecosystem: python\n    name: requests\n    version_constraint: '>=2.30'\n", "yaml")
    assert csv_rows == yaml_rows


def test_precise_purl_name_ecosystem_and_version():
    component = {"purl": "pkg:pypi/requests@2.31.0", "ecosystem": "python", "name": "requests", "version": "2.31.0"}
    assert component_matches({"purl": "pkg:pypi/requests"}, component)
    assert component_matches({"name": "requests", "ecosystem": "python", "version_constraint": ">=2.30"}, component)
    assert not component_matches({"name": "request"}, component)
    assert not component_matches({"name": "requests", "ecosystem": "npm"}, component)
    assert not component_matches({"purl": "pkg:pypi/requests@2.30.0"}, component)
    assert not version_matches("2.29", ">=2.30")


def test_invalid_import_does_not_guess():
    import pytest
    with pytest.raises(ValueError):
        parse_entries("entries:\n  - name: requests\n    version_constraint: probably-new\n", "yaml")
