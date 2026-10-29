#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Check out pkg/{distribution}.
With -u, fetch commits, and if changed, commit the latest hash.
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
    p.add_argument(
        '--update',
        '-u',
        action='store_true',
        default=False,
    )
    p.add_argument('--profile')
    return p.parse_args()


def read_config(distro: str):
    cmd = ['mkosi', '--json', '-d', distro, '-f', 'summary']
    if args.profile:
        cmd += ['--profile', args.profile]
    print(f'+ {shlex.join(cmd)}')
    text = subprocess.check_output(cmd, text=True)

    data = json.loads(text)
    images = {image['Image']: image for image in data['Images']}
    environment = images['build']['Environment']
    return json.loads(Path(f'packaging/{environment["PKG_SUBDIR"]}.json').read_text()) | {
        'subdir': environment.get('GIT_SUBDIR'),
        'pkg_subdir': environment['PKG_SUBDIR'],
    }


def commit_file(distro: str, files: list[Path], commit: str, changes: str):
    message = '\n'.join((f'mkosi: update {distro} commit reference to {commit}', '', changes))

    cmd = ['git', 'commit', '-m', message, *(str(file) for file in files)]
    print(f'+ {shlex.join(cmd)}')
    subprocess.check_call(cmd)


def checkout_distro(args, distro: str, config: dict):
    url = config['url']
    branch = config['branch']
    subdir = config['subdir']
    pkg_subdir = config['pkg_subdir']

    dest = Path(f'pkg/{pkg_subdir}')
    if dest.exists():
        print(f'{dest} already exists.')
        return

    # Do not checkout the full sources if the package is in a subdirectory,
    # a sparse checkout will be done after
    sparse = ['--no-checkout', '--filter=blob:none'] if subdir is not None else []

    # Only debian uses source-git for now…
    reference = ['--reference-if-able=.'] if distro == 'debian' else []

    cmd = [
        'git',
        'clone',
        url,
        f'--branch={branch}',
        *sparse,
        dest.as_posix(),
        *reference,
    ]
    print(f'+ {shlex.join(cmd)}')
    subprocess.check_call(cmd)

    # Sparse checkout if the package is in a subdirectory
    if subdir is not None:
        cmd = ['git', '-C', f'pkg/{pkg_subdir}', 'sparse-checkout', 'set', '--no-cone', f'{subdir}']
        print(f'+ {shlex.join(cmd)}')
        subprocess.check_call(cmd)

        cmd = ['git', '-C', f'pkg/{pkg_subdir}', 'checkout', 'HEAD']
        print(f'+ {shlex.join(cmd)}')
        subprocess.check_call(cmd)

    args.fetch = False  # no need to fetch if we just cloned


def update_distro(args, distro: str, config: dict):
    branch = config['branch']
    subdir = config['subdir']
    old_commit = config['commit']
    pkg_subdir = config['pkg_subdir']

    if args.fetch:
        cmd = [
            'git',
            '-C', f'pkg/{pkg_subdir}',
            'fetch',
            'origin',
            '-v',
            f'{branch}:remotes/origin/{branch}',
        ]  # fmt: skip
        print(f'+ {shlex.join(cmd)}')
        subprocess.check_call(cmd)

    cmd = ['git', '-C', f'pkg/{pkg_subdir}', 'switch', branch]
    print(f'+ {shlex.join(cmd)}')
    subprocess.check_call(cmd)

    cmd = ['git', '-C', f'pkg/{pkg_subdir}', 'log', '-n1', '--format=%H', f'refs/remotes/origin/{branch}']
    if subdir is not None:
        cmd += [f'{subdir}']
    print(f'+ {shlex.join(cmd)}')
    new_commit = subprocess.check_output(cmd, text=True).strip()

    if old_commit == new_commit:
        print(f'{pkg_subdir}: commit {new_commit!s} is still fresh')
        return

    cmd = [
        'git',
        '-C', f'pkg/{pkg_subdir}',
        'log',
        '--graph',
        '--no-merges',
        '--pretty=oneline',
        '--no-decorate',
        '--abbrev-commit',
        '--abbrev=10',
        f'{old_commit}..{new_commit}',
    ]  # fmt: skip
    if subdir is not None:
        cmd += [f'{subdir}']
    print(f'+ {shlex.join(cmd)}')
    changes = subprocess.check_output(cmd, text=True).strip()

    file = Path(f'packaging/{pkg_subdir}.json')
    pin = json.loads(file.read_text())
    pin['commit'] = new_commit
    file.write_text(json.dumps(pin, indent=2) + '\n')
    tocommit = [file]

    if pkg_subdir == 'fedora':
        packit = Path('.packit.yml')
        s = packit.read_text()
        assert old_commit in s
        new = s.replace(old_commit, new_commit)
        packit.write_text(new)
        tocommit += [packit]

    commit_file(distro, tocommit, new_commit, changes)


if __name__ == '__main__':
    args = parse_args()

    for distro in args.distribution:
        config = read_config(distro)
        checkout_distro(args, distro, config)
        if args.update:
            update_distro(args, distro, config)
