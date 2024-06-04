#!/usr/bin/python
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Fetch commits for pkg/{distribution} and, if changed, commit the latest hash.
"""

import argparse
import subprocess
from pathlib import Path

import mkosi

def parse_args():
    p = argparse.ArgumentParser(
        description=__doc__,
    )
    p.add_argument(
        'distribution',
        nargs='+',
    )
    p.add_argument(
        '--no-fetch',
        dest='fetch',
        action='store_false',
        default=True,
    )
    return p.parse_args()

def read_config(distro: str):
    _, images = mkosi.config.parse_config(['-d', distro])
    return images[-1]

def commit_file(distro: str, file: Path, commit: str, subject: str):
    message = '\n'.join((
        f'mkosi: update {distro} commit reference',
        '',
        f'"{subject}"'))

    subprocess.check_call(['git', 'commit', '-m', message, file])

def update_distro(args, distro: str):
    subprocess.check_call(['git', '-C', f'pkg/{distro}', 'fetch'])

    config = read_config(distro)

    branch = config.environment['GIT_BRANCH']
    old_commit = config.environment['GIT_COMMIT']

    new_commit = subprocess.check_output(
        ['git', '-C', f'pkg/{distro}', 'rev-parse', f'refs/remotes/origin/{branch}'],
        text=True,
    ).strip()
    # print(f'{branch=} {old_commit=!s} {new_commit=!s}')
    if old_commit == new_commit:
        print(f'Commit {new_commit!s} is still fresh')
        return

    subject = subprocess.check_output(
        ['git', '-C', f'pkg/{distro}', 'log', '-1', '--pretty=format:%s', new_commit],
        text=True,
    )

    conf_dir = Path('mkosi.images/system/mkosi.conf.d')
    files = conf_dir.glob('*/*.conf')
    for file in files:
        s = file.read_text()
        if old_commit in s:
            print(f'{file}: found old hash, updating…')
            new = s.replace(old_commit, new_commit)
            assert new != s
            file.write_text(new)
            commit_file(distro, file, new_commit, subject)
            break
    else:
        raise ValueError(f'Hash {new_commit} not found under {conf_dir}')

if __name__ == '__main__':
    args = parse_args()
    for distro in args.distribution:
        update_distro(args, distro)
