#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Fetch commits for pkg/{distribution} and, if changed, commit the latest hash.
"""

import argparse
import json
import shlex
import subprocess
from pathlib import Path

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
    cmd = ['mkosi', '--json', '-d', distro, 'summary']
    print(f"+ {shlex.join(cmd)}")
    text = subprocess.check_output(cmd, text=True)

    data = json.loads(text)
    return data['Images'][-1]

def commit_file(distro: str, file: Path, commit: str, changes: str):
    message = '\n'.join((
        f'mkosi: update {distro} commit reference',
        '',
        changes))

    cmd = ['git', 'commit', '-m', message, str(file)]
    print(f"+ {shlex.join(cmd)}")
    subprocess.check_call(cmd)

def update_distro(args, distro: str):
    cmd = ['git', '-C', f'pkg/{distro}', 'fetch']
    print(f"+ {shlex.join(cmd)}")
    subprocess.check_call(cmd)

    config = read_config(distro)

    branch = config['Environment']['GIT_BRANCH']
    old_commit = config['Environment']['GIT_COMMIT']

    cmd = ['git', '-C', f'pkg/{distro}', 'rev-parse', f'refs/remotes/origin/{branch}']
    print(f"+ {shlex.join(cmd)}")
    new_commit = subprocess.check_output(cmd, text=True).strip()

    if old_commit == new_commit:
        print(f'{distro}: commit {new_commit!s} is still fresh')
        return

    cmd = ['git', '-C', f'pkg/{distro}', 'log', '--graph',
           '--pretty=oneline', '--no-decorate', '--abbrev-commit', '--abbrev=10',
           f'{old_commit}..{new_commit}']
    print(f"+ {shlex.join(cmd)}")
    changes = subprocess.check_output(cmd, text=True).strip()

    conf_dir = Path('mkosi.images/system/mkosi.conf.d')
    files = conf_dir.glob('*/*.conf')
    for file in files:
        s = file.read_text()
        if old_commit in s:
            print(f'{distro}: {file}: found old hash, updating…')
            new = s.replace(old_commit, new_commit)
            assert new != s
            file.write_text(new)
            commit_file(distro, file, new_commit, changes)
            break
    else:
        raise ValueError(f'{distro}: hash {new_commit} not found under {conf_dir}')

if __name__ == '__main__':
    args = parse_args()
    for distro in args.distribution:
        update_distro(args, distro)
