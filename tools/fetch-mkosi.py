#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Check out mkosi into specified location.
With -u, if changed, commit the latest hash.
"""

import argparse
import shlex
import subprocess
import re
from pathlib import Path

URL = 'https://github.com/systemd/mkosi'
BRANCH = 'main'  # We only want to ever use commits on upstream 'main' branch
CONFIG = Path('mkosi/mkosi.conf')
WORKFLOWS = [Path('.github/workflows') / f for f in ['mkosi.yml', 'coverage.yml', 'linter.yml']]

def parse_args():
    p = argparse.ArgumentParser(
        description=__doc__,
    )
    p.add_argument(
        'dir',
        type=Path,
    )
    p.add_argument(
        '--update', '-u',
        action='store_true',
        default=False,
    )
    return p.parse_args()

def read_config():
    print(f'Reading {CONFIG}…')
    matches = [m.group(1)
               for line in open(CONFIG)
               if (m := re.match('^MinimumVersion=commit:([a-z0-9]{40})$',
                                 line.strip()))]
    assert len(matches) == 1
    return matches[0]

def commit_file(files: list[Path], commit: str, changes: str):
    message = '\n'.join((
        f'mkosi: update mkosi ref to {commit}',
        '',
        changes))

    cmd = ['git', 'commit', '-m', message, *(str(file) for file in files)]
    print(f"+ {shlex.join(cmd)}")
    subprocess.check_call(cmd)

def checkout_mkosi(args):
    if args.dir.exists():
        print(f'{args.dir} already exists.')
        return

    cmd = [
        'git', 'clone', URL,
        f'--branch={BRANCH}',
        args.dir.as_posix(),
    ]
    print(f"+ {shlex.join(cmd)}")
    subprocess.check_call(cmd)

def update_mkosi(args):
    old_commit = read_config()

    cmd = ['git', '-C', args.dir.as_posix(), 'rev-parse', f'refs/remotes/origin/{BRANCH}']
    print(f"+ {shlex.join(cmd)}")
    new_commit = subprocess.check_output(cmd, text=True).strip()

    if old_commit == new_commit:
        print(f'mkosi: commit {new_commit!s} is still fresh')
        return

    cmd = ['git', '-C', args.dir.as_posix(), 'log', '--graph', '--first-parent', '--no-merges',
           '--pretty=oneline', '--no-decorate', '--abbrev-commit', '--abbrev=10',
           f'{old_commit}..{new_commit}']
    print(f"+ {shlex.join(cmd)}")
    changes = subprocess.check_output(cmd, text=True).strip()

    for f in [CONFIG, *WORKFLOWS]:
        s = f.read_text()
        assert old_commit in s
        print(f'mkosi: {f}: found old hash, updating…')
        new = s.replace(old_commit, new_commit)
        assert new != s
        f.write_text(new)

    commit_file([CONFIG, *WORKFLOWS], new_commit, changes)

if __name__ == '__main__':
    args = parse_args()
    checkout_mkosi(args)
    if args.update:
        update_mkosi(args)
