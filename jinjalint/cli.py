"""jinjalint

Usage:
  jinjalint [-v | --verbose] [-p | --print] [-j | --json] [--config CONFIG]
            [--parse-only] [--exit-zero] [--extension EXT | -e EXT]...
            [--select CHK | -s CHK]... [--exclude CHK | -x CHK]... [INPUT ...]
  jinjalint (-h | --help)
  jinjalint --version

Options:
  -h --help             Show this help message and exit.
  --version             Show version information and exit.
  -v --verbose          Verbose mode.
  -p --print            Print input files in tree format.
  -j --json             Output results in JSON format.
  -c --config CONFIG    Specify the configuration file.
  --parse-only          Don’t lint, check for syntax errors and exit.
  --exit-zero           Exit "0" even if there are issues.
  -e --extension EXT    Extension of the files to analyze (used if INPUT
                        contains directories to crawl).
                        [default: html jinja twig]
  -s --select CHK       List of checks to include when running.
  -x --exclude CHK      List of checks to exclude when running.

The configuration file must be a valid Python file.
"""
import json
import sys

from docopt import docopt

from .lint import lint, resolve_file_paths
from .config import parse_config
from ._version import get_versions


def print_issues(issues, config):
    sorted_issues = sorted(
        issues,
        key=lambda i: (
            i.location.file_path,
            i.location.line,
            i.location.column
        ),
    )

    for issue in sorted_issues:
        print(str(issue))


def main():
    arguments = docopt(__doc__)

    input_names = arguments['INPUT'] or ['.']
    extensions = ['.' + e for e in arguments['--extension']]
    verbose = arguments['--verbose']

    if arguments['--version']:
        print(get_versions()['version'])
        return

    if arguments['--config']:
        if verbose:
            print('Using configuration file {}'.format(arguments['--config']))
        config = parse_config(arguments['--config'])
    else:
        config = {}

    config['verbose'] = verbose
    config['parse_only'] = arguments['--parse-only']
    config['print'] = arguments['--print']
    config['select'] = arguments['--select']
    config['exclude'] = arguments['--exclude']

    paths = list(resolve_file_paths(input_names, extensions=extensions))

    if verbose:
        print('Files being analyzed:')
        print('\n'.join(str(p) for p in paths))
        print()

    issues = lint(paths, config)

    if arguments['--json']:
        result = [
            {
                'message': issue.message,
                'code': issue.code,
                'file_path': str(issue.location.file_path),
                'line': issue.location.line,
                'column': issue.location.column,
            }
            for issue in issues
        ]
        json.dump(result, sys.stdout)
    else:
        print_issues(issues, config)

    if any(issues):
        code = 0 if arguments['--exit-zero'] else 1
        sys.exit(code)


if __name__ == '__main__':
    main()
