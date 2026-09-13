from pathlib import Path


def _files():
    root = Path(__file__).parents[1]
    return next(root.glob("app/**/_overview_panels.html")), next(root.glob("app/**/overview-pagination.js"))


def test_top_overview_panels_have_independent_client_pagination():
    template, script = _files()
    html = template.read_text(encoding="utf-8")
    js = script.read_text(encoding="utf-8")

    assert html.count("overview-paginated") == 3
    assert html.count('data-page-size="10"') == 3
    assert html.count("data-overview-pagination") == 3
    assert "let page = 1" in js
    assert "rows.forEach" in js
    assert "fetch(" not in js
    assert "XMLHttpRequest" not in js

