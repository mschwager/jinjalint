import textwrap

from . import check
from . import issue
from . import lint


def get_file(html):
    config = {}

    return lint.parse_source((textwrap.dedent(html), config))


def test_check_csrf_protection_missing_token():
    html = """
    <html>
        <body>
            <form method="post">
                <input name="foo" value="bar"/>
            </form>
        </body>
    </html>
    """

    errors, jl_file = get_file(html)
    result = check.check_csrf_protection(jl_file, {})
    expected = [
        issue.Issue(
            issue.IssueLocation(
                file_path=None,
                line=3,
                column=8
            ),
            check.CSRF_ISSUE_MESSAGE,
            check.CSRF_ISSUE_CODE
        )
    ]

    assert result == expected


def test_check_csrf_protection_input_field_present():
    html = """
    <html>
        <body>
            <form method="post">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
            </form>
        </body>
    </html>
    """

    errors, jl_file = get_file(html)
    result = check.check_csrf_protection(jl_file, {})
    expected = []

    assert result == expected


def test_check_csrf_protection_flask_form_present():
    html = """
    <html>
        <body>
            <form method="post">
                {{ form.csrf_token }}
            </form>
        </body>
    </html>
    """

    errors, jl_file = get_file(html)
    result = check.check_csrf_protection(jl_file, {})
    expected = []

    assert result == expected


def test_check_anchor_target_blank_missing_rel():
    html = """
    <html>
        <body>
            <a href="https://example.com" target="_blank">Test</a>
        </body>
    </html>
    """

    errors, jl_file = get_file(html)
    result = check.check_anchor_target_blank(jl_file, {})
    expected = [
        issue.Issue(
            issue.IssueLocation(
                file_path=None,
                line=3,
                column=8
            ),
            check.ANCHOR_ISSUE_MESSAGE,
            check.ANCHOR_ISSUE_CODE
        )
    ]

    assert result == expected


def test_check_anchor_target_blank_missing_noreferrer():
    html = """
    <html>
        <body>
            <a href="https://example.com" target="_blank" rel="noopener">Test</a>
        </body>
    </html>
    """

    errors, jl_file = get_file(html)
    result = check.check_anchor_target_blank(jl_file, {})
    expected = [
        issue.Issue(
            issue.IssueLocation(
                file_path=None,
                line=3,
                column=8
            ),
            check.ANCHOR_ISSUE_MESSAGE,
            check.ANCHOR_ISSUE_CODE
        )
    ]

    assert result == expected


def test_check_anchor_target_blank_missing_noopener():
    html = """
    <html>
        <body>
            <a href="https://example.com" target="_blank" rel="noreferrer">Test</a>
        </body>
    </html>
    """

    errors, jl_file = get_file(html)
    result = check.check_anchor_target_blank(jl_file, {})
    expected = [
        issue.Issue(
            issue.IssueLocation(
                file_path=None,
                line=3,
                column=8
            ),
            check.ANCHOR_ISSUE_MESSAGE,
            check.ANCHOR_ISSUE_CODE
        )
    ]

    assert result == expected


def test_check_anchor_target_blank_both_rel_present():
    html = """
    <html>
        <body>
            <a href="https://example.com" target="_blank" rel="noopener noreferrer">Test</a>
        </body>
    </html>
    """

    errors, jl_file = get_file(html)
    result = check.check_anchor_target_blank(jl_file, {})
    expected = []

    assert result == expected


def test_check_anchor_target_blank_missing_target_blank():
    html = """
    <html>
        <body>
            <a href="https://example.com">Test</a>
        </body>
    </html>
    """

    errors, jl_file = get_file(html)
    result = check.check_anchor_target_blank(jl_file, {})
    expected = []

    assert result == expected


def test():
    test_check_csrf_protection_missing_token()
    test_check_csrf_protection_input_field_present()
    test_check_csrf_protection_flask_form_present()

    test_check_anchor_target_blank_missing_rel()
    test_check_anchor_target_blank_missing_noreferrer()
    test_check_anchor_target_blank_missing_noopener()
    test_check_anchor_target_blank_both_rel_present()
    test_check_anchor_target_blank_missing_target_blank()
