import re
import operator

from . import ast
from .util import flatten
from .issue import Issue, IssueLocation


WHITESPACE_INDENT_RE = re.compile(r'^\s*')
INDENT_RE = re.compile('^ *')


def get_line_beginning(source, node):
    source = source[:node.begin.index]
    return source.split('\n')[-1]


def get_indent_level(source, node):
    """
    Returns the number of whitespace characters before the given node,
    in the first line of node.
    Returns `None` if some characters before the given node in this
    line aren’t whitespace.

    For example, if the source file contains `   <br /> ` on a line,
    `get_indent_level` will return 3 if called with the `<br />` tag
    as `node`.
    """
    beginning = get_line_beginning(source, node)
    if beginning and not beginning.isspace():
        return None
    return len(beginning)


def contains_exclusively(string, char):
    return string.replace(char, '') == ''


def truncate(s, length=16):
    return s[:length] + (s[length:] and '…')


def check_indentation(file, config):
    indent_size = config.get('indent_size', 4)

    issues = []

    def add_issue(location, msg):
        issues.append(Issue.from_ast(file, location, msg))

    def check_indent(expected_level, node, inline=False,
                     allow_same_line=False):
        node_level = get_indent_level(file.source, node)
        if node_level is None:
            if not inline and not allow_same_line:
                node_s = repr(truncate(str(node)))
                add_issue(node.begin, node_s + ' should be on the next line')
            return

        if node_level != expected_level:
            msg = 'Bad indentation, expected {}, got {}'.format(
                expected_level, node_level,
            )
            add_issue(node.begin, msg)

    def check_attribute(expected_level, attr, inline=False, **_):
        if not attr.value:
            return

        if attr.begin.line != attr.value.begin.line:
            add_issue(
                attr.begin,
                'The value must begin on line {}'.format(attr.begin.line),
            )
        check_content(
            expected_level,
            attr.value,
            inline=attr.value.begin.line == attr.value.end.line,
            allow_same_line=True
        )

    def check_opening_tag(expected_level, tag, inline=False, **_):
        if len(tag.attributes) and tag.begin.line != tag.end.line:
            first = tag.attributes[0]
            check_node(
                expected_level + indent_size,
                first,
                inline=isinstance(first, ast.Attribute),
            )
            attr_level = len(get_line_beginning(file.source, first))
            for attr in tag.attributes[1:]:
                # attr may be a JinjaElement
                check_node(
                    expected_level if inline else attr_level,
                    attr,
                    inline=isinstance(attr, ast.Attribute),
                )

    def check_comment(expected_level, tag, **_):
        pass

    def check_jinja_comment(expected_level, tag, **_):
        pass

    def check_jinja_tag(expected_level, tag, **_):
        pass

    def check_string(expected_level, string, inline=False,
                     allow_same_line=False):
        if string.value.begin.line != string.value.end.line:
            inline = False
        check_content(string.value.begin.column, string.value, inline=inline,
                      allow_same_line=allow_same_line)

    def check_integer(expected_level, integer, **_):
        pass

    def get_first_child_node(parent):
        for c in parent:
            if isinstance(c, ast.Node):
                return c
        return None

    def has_jinja_element_child(parent, tag_name):
        child = get_first_child_node(parent)
        return (
            isinstance(child, ast.JinjaElement) and
            child.parts[0].tag.name == tag_name
        )

    def check_jinja_element_part(expected_level, part, inline=False,
                                 allow_same_line=False):
        check_node(expected_level, part.tag, inline=inline,
                   allow_same_line=allow_same_line)
        element_names_to_not_indent = (
            config.get('jinja_element_names_to_not_indent', [])
        )
        do_not_indent = part.tag.name in element_names_to_not_indent and \
            has_jinja_element_child(part.content, part.tag.name)
        if part.begin.line != part.end.line:
            inline = False
        shift = 0 if inline or do_not_indent else indent_size
        content_level = expected_level + shift
        if part.content is not None:
            check_content(content_level, part.content, inline=inline)

    def check_jinja_optional_container_if(expected_level, o_if, html_tag, c_if,
                                          inline=False):
        check_indent(expected_level, o_if, inline=inline)
        shift = 0 if inline else indent_size
        if isinstance(html_tag, ast.OpeningTag):
            check_opening_tag(expected_level + shift, html_tag, inline=inline)
        elif isinstance(html_tag, ast.ClosingTag):
            check_indent(expected_level + shift, html_tag, inline=inline)
        else:
            raise AssertionError('invalid tag')
        check_indent(expected_level, c_if, inline=inline)
        return inline

    def check_jinja_optional_container(expected_level, element,
                                       inline=False, **_):
        if element.first_opening_if.begin.line == \
                element.second_opening_if.end.line:
            inline = True

        inline = check_jinja_optional_container_if(
            expected_level,
            element.first_opening_if,
            element.opening_tag,
            element.first_closing_if,
            inline=inline)

        check_content(expected_level, element.content, inline=inline)

        check_jinja_optional_container_if(
            expected_level,
            element.second_opening_if,
            element.closing_tag,
            element.second_closing_if,
            inline=inline)

    def check_jinja_element(expected_level, element, inline=False,
                            allow_same_line=False):
        if element.begin.line == element.end.line:
            inline = True
        for part in element.parts:
            check_node(
                expected_level,
                part,
                inline=inline,
                allow_same_line=allow_same_line)
        if element.closing_tag is not None:
            check_indent(expected_level, element.closing_tag, inline=inline)

    def check_jinja_variable(expected_level, var, **_):
        pass

    def check_element(expected_level, element, inline=False, **_):
        opening_tag = element.opening_tag
        closing_tag = element.closing_tag
        check_opening_tag(expected_level, opening_tag, inline=inline)
        if not closing_tag:
            return
        if inline or opening_tag.end.line == closing_tag.begin.line:
            check_content(expected_level, element.content, inline=True)
        else:
            check_content(
                expected_level + indent_size,
                element.content,
            )
            check_indent(expected_level, closing_tag)

    def check_node(expected_level, node, inline=False,
                   allow_same_line=False, **_):
        check_indent(
            expected_level,
            node,
            inline=inline,
            allow_same_line=allow_same_line
        )

        types_to_functions = {
            ast.Attribute: check_attribute,
            ast.Comment: check_comment,
            ast.Element: check_element,
            ast.Integer: check_integer,
            ast.JinjaComment: check_jinja_comment,
            ast.JinjaElement: check_jinja_element,
            ast.JinjaElementPart: check_jinja_element_part,
            ast.JinjaOptionalContainer: check_jinja_optional_container,
            ast.JinjaTag: check_jinja_tag,
            ast.JinjaVariable: check_jinja_variable,
            ast.String: check_string,
        }

        func = types_to_functions.get(type(node))
        if func is None:
            raise Exception('Unexpected {!r} node at {}'.format(
                type(node), node.begin,
            ))

        func(expected_level, node, inline=inline,
             allow_same_line=allow_same_line)

    def check_content_str(expected_level, string, parent_node):
        lines = string.split('\n')
        expected_indent = expected_level * ' '

        indent = INDENT_RE.match(lines[0]).group(0)

        if len(indent) > 1:
            msg = (
                'Expected at most one space at the beginning of the text '
                'node, got {} spaces'
            ).format(len(indent))
            add_issue(parent_node.begin, msg)

        # skip the first line since there is certainly an HTML tag before
        for line in lines[1:]:
            if line.strip() == '':
                continue
            indent = INDENT_RE.match(line).group(0)
            if indent != expected_indent:
                msg = 'Bad text indentation, expected {}, got {}'.format(
                    expected_level, len(indent),
                )
                add_issue(parent_node.begin, msg)

    def check_content(expected_level, parent_node, inline=False,
                      allow_same_line=False):
        inline_parent = inline
        for i, child in enumerate(parent_node):
            next_child = get_first_child_node(parent_node[i + 1:])

            if isinstance(child, str):
                if i == 0 and '<!DOCTYPE' in child:
                    continue

                check_content_str(expected_level, child, parent_node)
                if not child.strip(' '):
                    inline = True
                elif child.strip() and child.count('\n') <= 1:
                    inline = True
                elif (next_child and
                      child.strip() and
                      not child.replace(' ', '').endswith('\n')):
                    inline = True
                elif child.replace(' ', '').endswith('\n\n'):
                    inline = False
                if inline_parent and not inline:
                    msg = (
                        'An inline parent element must only contain '
                        'inline children'
                    )
                    add_issue(parent_node.begin, msg)
                continue

            if isinstance(child, ast.Node):
                if next_child and child.begin.line == next_child.end.line:
                    inline = True
                check_node(
                    expected_level,
                    child,
                    inline=inline,
                    allow_same_line=allow_same_line
                )
                continue

            raise Exception()

    check_content(0, file.tree)

    return issues


class CheckNode:
    def __init__(self, value):
        self.value = value
        self.children = []

    def __str__(self, level=0):
        name = getattr(self.value, "name", None)

        attributes = []
        if getattr(self.value, "opening_tag", None):
            attributes = [
                (str(n.name), str(n.value).strip("\"'"))
                for n in self.value.opening_tag.attributes.nodes
            ]

        result = (
            "  " * level
            + "{}: name={!r} attributes={!r}".format(type(self.value), name, attributes)
            + "\n"
        )

        for child in self.children:
            result += child.__str__(level + 1)

        return result


def print_tree(node):
    root = CheckNode(None)
    build_tree(root, node)
    print(root)


def build_tree(root, node):
    if isinstance(node, str) or node is None:
        return

    for child in node.nodes:
        new_node = CheckNode(child)
        if getattr(child, "content", None):
            build_tree(new_node, child.content)
        root.children.append(new_node)


def form_csrf_protection(node):
    attributes = []
    if getattr(node.value, "opening_tag", None):
        attributes = [
            (str(n.name), str(n.value).strip("\"'"))
            for n in node.value.opening_tag.attributes.nodes
        ]
    is_csrf_jinja_variable = (
        isinstance(node.value, ast.JinjaVariable)
        and node.value.content.lower() == "form.csrf_token"
    )
    is_csrf_input = (
        isinstance(node.value, ast.Element)
        and ("name", "csrf_token") in attributes
        and ("value", "{{ csrf_token() }}") in attributes
    )

    if is_csrf_jinja_variable or is_csrf_input:
        return True

    if not node.children:
        return False

    return any(form_csrf_protection(child) for child in node.children)


CSRF_ISSUE_MESSAGE = "Form missing CSRF protection"


def _check_csrf_protection_helper(node, file):
    name = getattr(node.value, "name", None)
    is_form = (
        isinstance(node.value, ast.Element)
        and name and name.lower() == "form"
    )

    if is_form:
        form_has_csrf_protection = form_csrf_protection(node)
        if not form_has_csrf_protection:
            issue_location = IssueLocation(
                file_path=file.path,
                line=node.value.begin.line,
                column=node.value.begin.column
            )
            return [Issue(issue_location, CSRF_ISSUE_MESSAGE)]
        return []

    if not node.children:
        return []

    return sum((_check_csrf_protection_helper(child, file) for child in node.children), [])


def check_csrf_protection(file, config):
    root = CheckNode(None)
    build_tree(root, file.tree)

    # https://flask-wtf.readthedocs.io/en/stable/csrf.html
    return _check_csrf_protection_helper(root, file)


ANCHOR_ISSUE_MESSAGE = "Anchor with 'target=_blank' missing 'noopener' and/or 'noreferrer'"


def _check_anchor_target_blank_helper(node, file):
    name = getattr(node.value, "name", None)
    is_anchor = (
        isinstance(node.value, ast.Element)
        and name and name.lower() == "a"
    )
    attributes = []
    if getattr(node.value, "opening_tag", None):
        attributes = [
            (str(n.name), str(n.value).strip("\"'"))
            for n in node.value.opening_tag.attributes.nodes
        ]
    is_insecure_anchor = (
        is_anchor
        and ("target", "_blank") in attributes
        and not any(
            k == "rel"
            and "noopener" in v
            and "noreferrer" in v
            for k, v in attributes
        )
    )

    if is_insecure_anchor:
        issue_location = IssueLocation(
            file_path=file.path,
            line=node.value.begin.line,
            column=node.value.begin.column
        )
        return [Issue(issue_location, ANCHOR_ISSUE_MESSAGE)]

    if not node.children:
        return []

    return sum((_check_anchor_target_blank_helper(child, file) for child in node.children), [])


def check_anchor_target_blank(file, config):
    root = CheckNode(None)
    build_tree(root, file.tree)
    return _check_anchor_target_blank_helper(root, file)


ANCHOR_HREF_TEMPLATE_ISSUE_MESSAGE = "Anchor href with Jinja template - XSS possible by 'javascript:' URI"


def _check_anchor_href_template_helper(node, file):
    name = getattr(node.value, "name", None)
    is_anchor = (
        isinstance(node.value, ast.Element)
        and name and name.lower() == "a"
    )
    attributes = []
    if getattr(node.value, "opening_tag", None):
        attributes = [
            (str(n.name), str(n.value))
            for n in node.value.opening_tag.attributes.nodes
        ]

    anchor_href_template = is_anchor and any(
        "{{" in attr[1] and "}}" in attr[1]
        for attr in attributes
    )

    issues = []
    if anchor_href_template:
        issue_location = IssueLocation(
            file_path=file.path,
            line=node.value.begin.line,
            column=node.value.begin.column
        )
        issues = [Issue(issue_location, ANCHOR_HREF_TEMPLATE_ISSUE_MESSAGE)]

    return issues + sum(
        (_check_anchor_href_template_helper(child, file) for child in node.children),
        []
    )


def check_anchor_href_template(file, config):
    root = CheckNode(None)
    build_tree(root, file.tree)

    # https://flask.palletsprojects.com/en/1.1.x/security/#cross-site-scripting-xss
    return _check_anchor_href_template_helper(root, file)


DOCTYPE_ISSUE_MESSAGE = "Include HTML doctype like '<!DOCTYPE html>' to avoid interpretation conflict (XSS)"


def check_html_doctype(file, config):
    src = file.source.lower()

    if r"<html" in src and r"</html" in src and r"<!doctype" not in src:
        # See https://html5sec.org/ for why quirks mode can be bad
        issue_location = IssueLocation(
            file_path=file.path,
            line=1,
            column=0
        )
        return [Issue(issue_location, DOCTYPE_ISSUE_MESSAGE)]

    return []


CHARSET_ISSUE_MESSAGE = "Include HTML charset like '<meta charset=\"UTF-8\">' to avoid interpretation conflict (XSS)"


def _check_html_charset_helper(node, file):
    name = getattr(node.value, "name", None)
    is_meta = (
        isinstance(node.value, ast.Element)
        and name and name.lower() == "meta"
    )
    attributes = []
    if getattr(node.value, "opening_tag", None):
        attributes = [
            (str(n.name), str(n.value).strip("\"'"))
            for n in node.value.opening_tag.attributes.nodes
        ]
    is_meta_charset = (
        is_meta
        and "charset" in operator.itemgetter(0)(attributes)
    )

    if is_meta_charset:
        return True

    if not node.children:
        return False

    return any(_check_html_charset_helper(child, file) for child in node.children)


def check_html_charset(file, config):
    root = CheckNode(None)
    build_tree(root, file.tree)
    src = file.source.lower()

    if r"<html" in src and r"</html" in src and not _check_html_charset_helper(root, file):
        # See the following for why missing charset can be bad
        #   * https://html5sec.org/
        #   * https://portswigger.net/kb/issues/00800200_html-does-not-specify-charset
        issue_location = IssueLocation(
            file_path=file.path,
            line=1,
            column=0
        )
        return [Issue(issue_location, CHARSET_ISSUE_MESSAGE)]

    return []


CONTENT_TYPE_ISSUE_MESSAGE = "Include HTML content-type like '<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\">' to avoid interpretation conflict (XSS)"


def _check_html_content_type_helper(node, file):
    name = getattr(node.value, "name", None)
    is_meta = (
        isinstance(node.value, ast.Element)
        and name and name.lower() == "meta"
    )
    attributes = []
    if getattr(node.value, "opening_tag", None):
        attributes = [
            (str(n.name), str(n.value).strip("\"'"))
            for n in node.value.opening_tag.attributes.nodes
        ]
    is_meta_content_type = (
        is_meta
        and ("http-equiv", "Content-Type") in attributes
    )

    if is_meta_content_type:
        return True

    if not node.children:
        return False

    return any(_check_html_content_type_helper(child, file) for child in node.children)


def check_html_content_type(file, config):
    root = CheckNode(None)
    build_tree(root, file.tree)
    src = file.source.lower()

    if r"<html" in src and r"</html" in src and not _check_html_content_type_helper(root, file):
        # See the following for why missing content type can be bad
        #   * https://html5sec.org/
        #   * https://portswigger.net/kb/issues/00800500_content-type-is-not-specified
        issue_location = IssueLocation(
            file_path=file.path,
            line=1,
            column=0
        )
        return [Issue(issue_location, CONTENT_TYPE_ISSUE_MESSAGE)]

    return []


UNQUOTED_ATTRIBUTE_ISSUE_MESSAGE = "HTML element with unquoted attribute - XSS possible by attribute injection"


def _check_unquoted_attributes_helper(node, file):
    attributes = []
    if getattr(node.value, "opening_tag", None):
        attributes = [
            (str(n.name), str(n.value))
            for n in node.value.opening_tag.attributes.nodes
        ]

    def unquoted_attr(attr):
        return (
            attr
            and '{{' in attr
            and '}}' in attr
            and (attr[0] not in '\'"' or attr[len(attr) - 1] not in '\'"')
        )

    unquoted_attribute = any(unquoted_attr(attr[1]) for attr in attributes)

    issues = []
    if unquoted_attribute:
        issue_location = IssueLocation(
            file_path=file.path,
            line=node.value.begin.line,
            column=node.value.begin.column
        )
        issues = [Issue(issue_location, UNQUOTED_ATTRIBUTE_ISSUE_MESSAGE)]

    return issues + sum(
        (_check_unquoted_attributes_helper(child, file) for child in node.children),
        []
    )


def check_unquoted_attributes(file, config):
    root = CheckNode(None)
    build_tree(root, file.tree)

    # https://flask.palletsprojects.com/en/1.1.x/security/#cross-site-scripting-xss
    return _check_unquoted_attributes_helper(root, file)


def check_space_only_indent(file, _config):
    issues = []
    for i, line in enumerate(file.lines):
        indent = WHITESPACE_INDENT_RE.match(line).group(0)
        if not contains_exclusively(indent, ' '):
            loc = IssueLocation(
                file_path=file.path,
                line=i,
                column=0,
            )
            issue = Issue(loc, 'Should be indented with spaces')
            issues.append(issue)
    return issues


checks = [
    check_space_only_indent,
    check_indentation,
    check_csrf_protection,
    check_anchor_target_blank,
    check_anchor_href_template,
    check_html_doctype,
    check_html_charset,
    check_html_content_type,
    check_unquoted_attributes,
]


def check_file(file, config):
    return set(flatten(check(file, config) for check in checks))


def check_files(files, config):
    return flatten(check_file(file, config) for file in files)
