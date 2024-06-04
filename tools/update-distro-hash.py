#!/usr/bin/python
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Fetch commits for pkg/{distribution} and, if changed, commit the latest hash.
"""

import argparse
from pathlib import Path

import pygit2
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

def commit_file(file: Path, distro: str, commit: pygit2.Object):
    repo = pygit2.Repository('.')

    title = commit.message.split('\n')[0]
    message = '\n'.join((
        f'mkosi: update {distro} commit reference',
        '',
        f'"{title}"'))

    index = repo.index
    index.add(file)
    index.write()
    tree = index.write_tree()

    parent, ref = repo.resolve_refish(refish=repo.head.name)
    signature = repo.default_signature
    print(f"Committing tree {tree} with author '{signature.name} <{signature.email}>' on branch '{ref.shorthand}'")
    oid = repo.create_commit(ref.name, signature, signature, message, tree, [parent.oid])
    print(f'Committed {oid} to repository')

def update_distro(args, distro: str):
    repo = pygit2.Repository(f'pkg/{distro}')

    if args.fetch:
        trans = repo.remotes[0].fetch()
        print(f'Fetch fetched {trans.received_bytes} bytes, {trans.received_objects} objects')

    config = read_config(distro)

    branch = config.environment['GIT_BRANCH']
    old_commit = config.environment['GIT_COMMIT']

    ref = repo.lookup_reference(f'refs/remotes/origin/{branch}')
    new_commit = ref.peel()

    print(f'{branch=} {old_commit=!s} new_commit={new_commit.hex}')

    if old_commit == new_commit.hex:
        return

    conf_dir = Path('mkosi.images/system/mkosi.conf.d')
    files = conf_dir.glob('*/*.conf')
    for file in files:
        s = file.read_text()
        if old_commit in s:
            print(f'{file}: found old hash, updating…')
            new = s.replace(old_commit, new_commit.hex)
            assert new != s
            file.write_text(new)
            commit_file(file, distro, new_commit)
            break
    else:
        raise ValueError(f'Hash {new_commit} not found under {conf_dir}')

if __name__ == '__main__':
    args = parse_args()
    for distro in args.distribution:
        update_distro(args, distro)
