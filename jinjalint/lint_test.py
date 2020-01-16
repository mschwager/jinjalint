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
            check.FORM_MISSING_CSRF_ISSUE_MESSAGE,
            check.FORM_MISSING_CSRF_ISSUE_CODE
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
    result = set(
        check.check_anchor_target_blank_noopener(jl_file, {})
        + check.check_anchor_target_blank_noreferrer(jl_file, {})
    )
    expected = {
        issue.Issue(
            issue.IssueLocation(
                file_path=None,
                line=3,
                column=8
            ),
            check.ANCHOR_TARGET_BLANK_NOOPENER_ISSUE_MESSAGE,
            check.ANCHOR_TARGET_BLANK_NOOPENER_ISSUE_CODE
        ),
        issue.Issue(
            issue.IssueLocation(
                file_path=None,
                line=3,
                column=8
            ),
            check.ANCHOR_TARGET_BLANK_NOREFERRER_ISSUE_MESSAGE,
            check.ANCHOR_TARGET_BLANK_NOREFERRER_ISSUE_CODE
        )
    }

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
    result = set(
        check.check_anchor_target_blank_noopener(jl_file, {})
        + check.check_anchor_target_blank_noreferrer(jl_file, {})
    )
    expected = {
        issue.Issue(
            issue.IssueLocation(
                file_path=None,
                line=3,
                column=8
            ),
            check.ANCHOR_TARGET_BLANK_NOREFERRER_ISSUE_MESSAGE,
            check.ANCHOR_TARGET_BLANK_NOREFERRER_ISSUE_CODE
        )
    }

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
    result = set(
        check.check_anchor_target_blank_noopener(jl_file, {})
        + check.check_anchor_target_blank_noreferrer(jl_file, {})
    )
    expected = {
        issue.Issue(
            issue.IssueLocation(
                file_path=None,
                line=3,
                column=8
            ),
            check.ANCHOR_TARGET_BLANK_NOOPENER_ISSUE_MESSAGE,
            check.ANCHOR_TARGET_BLANK_NOOPENER_ISSUE_CODE
        )
    }

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
    result = set(
        check.check_anchor_target_blank_noopener(jl_file, {})
        + check.check_anchor_target_blank_noreferrer(jl_file, {})
    )
    expected = set()

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
    result = set(
        check.check_anchor_target_blank_noopener(jl_file, {})
        + check.check_anchor_target_blank_noreferrer(jl_file, {})
    )
    expected = set()

    assert result == expected


def test_check_anchor_target_blank_url_for():
    html = """
    <html>
        <body>
            <a href="{{ url_for('foo') }}">Test</a>
        </body>
    </html>
    """

    errors, jl_file = get_file(html)
    result = set(
        check.check_anchor_target_blank_noopener(jl_file, {})
        + check.check_anchor_target_blank_noreferrer(jl_file, {})
    )
    expected = set()

    assert result == expected


def test_check_anchor_href_template_present():
    html = """
    <html>
        <body>
            <a href="{{ value }}">Test</a>
        </body>
    </html>
    """

    errors, jl_file = get_file(html)
    result = check.check_anchor_href_template(jl_file, {})
    expected = [
        issue.Issue(
            issue.IssueLocation(
                file_path=None,
                line=3,
                column=8
            ),
            check.ANCHOR_HREF_TEMPLATE_ISSUE_MESSAGE,
            check.ANCHOR_HREF_TEMPLATE_ISSUE_CODE
        )
    ]

    assert result == expected


def test_check_anchor_href_template_url_for():
    html = """
    <html>
        <body>
            <a href="{{ url_for('foo') }}">Test</a>
        </body>
    </html>
    """

    errors, jl_file = get_file(html)
    result = check.check_anchor_href_template(jl_file, {})
    expected = []

    assert result == expected


def test_check_unquoted_attributes_present():
    html = """
    <html>
        <body>
            <input name={{ value }} value="foo" />
        </body>
    </html>
    """

    errors, jl_file = get_file(html)
    result = check.check_unquoted_attributes(jl_file, {})
    expected = [
        issue.Issue(
            issue.IssueLocation(
                file_path=None,
                line=3,
                column=8
            ),
            check.UNQUOTED_ATTRIBUTE_ISSUE_MESSAGE,
            check.UNQUOTED_ATTRIBUTE_ISSUE_CODE
        )
    ]

    assert result == expected


def test_check_unquoted_attributes_single_quote():
    html = """
    <html>
        <body>
            <input name='{{ value }}' value="foo" />
        </body>
    </html>
    """

    errors, jl_file = get_file(html)
    result = check.check_unquoted_attributes(jl_file, {})
    expected = []

    assert result == expected


def test_check_unquoted_attributes_double_quote():
    html = """
    <html>
        <body>
            <input name="{{ value }}" value="foo" />
        </body>
    </html>
    """

    errors, jl_file = get_file(html)
    result = check.check_unquoted_attributes(jl_file, {})
    expected = []

    assert result == expected


def test_check_unquoted_attributes_url_for():
    html = """
    <html>
        <body>
            <input name={{ url_for('foo') }} value="foo" />
        </body>
    </html>
    """

    errors, jl_file = get_file(html)
    result = check.check_unquoted_attributes(jl_file, {})
    expected = []

    assert result == expected


def test_check_html_doctype_missing():
    html = """
    <html>
        <head>
        </head>
        <body>
        </body>
    </html>
    """

    errors, jl_file = get_file(html)
    result = check.check_html_doctype(jl_file, {})
    expected = [
        issue.Issue(
            issue.IssueLocation(
                file_path=None,
                line=1,
                column=0
            ),
            check.DOCTYPE_ISSUE_MESSAGE,
            check.DOCTYPE_ISSUE_CODE
        )
    ]

    assert result == expected


def test_check_html_doctype_present():
    html = """
    <!DOCTYPE html>
    <html>
        <head>
        </head>
        <body>
        </body>
    </html>
    """

    errors, jl_file = get_file(html)
    result = check.check_html_doctype(jl_file, {})
    expected = []

    assert result == expected


def test_check_html_charset_missing():
    html = """
    <html>
        <head>
        </head>
        <body>
        </body>
    </html>
    """

    errors, jl_file = get_file(html)
    result = check.check_html_charset(jl_file, {})
    expected = [
        issue.Issue(
            issue.IssueLocation(
                file_path=None,
                line=1,
                column=0
            ),
            check.CHARSET_ISSUE_MESSAGE,
            check.CHARSET_ISSUE_CODE
        )
    ]

    assert result == expected


def test_check_html_charset_present():
    html = """
    <html>
        <head>
            <meta charset="UTF-8">
        </head>
        <body>
        </body>
    </html>
    """

    errors, jl_file = get_file(html)
    result = check.check_html_charset(jl_file, {})
    expected = []

    assert result == expected


def test_check_html_content_type_missing():
    html = """
    <html>
        <head>
        </head>
        <body>
        </body>
    </html>
    """

    errors, jl_file = get_file(html)
    result = check.check_html_content_type(jl_file, {})
    expected = [
        issue.Issue(
            issue.IssueLocation(
                file_path=None,
                line=1,
                column=0
            ),
            check.CONTENT_TYPE_ISSUE_MESSAGE,
            check.CONTENT_TYPE_ISSUE_CODE
        )
    ]

    assert result == expected


def test_check_html_content_type_present():
    html = """
    <html>
        <head>
            <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        </head>
        <body>
        </body>
    </html>
    """

    errors, jl_file = get_file(html)
    result = check.check_html_content_type(jl_file, {})
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

    test_check_anchor_href_template_present()
    test_check_anchor_href_template_url_for()

    test_check_unquoted_attributes_present()
    test_check_unquoted_attributes_single_quote()
    test_check_unquoted_attributes_double_quote()
    test_check_unquoted_attributes_url_for()

    test_check_html_doctype_missing()
    test_check_html_doctype_present()

    test_check_html_charset_missing()
    test_check_html_charset_present()

    test_check_html_content_type_missing()
    test_check_html_content_type_present()
