#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import json
import os
import sys


def main() -> int:
    build_root = os.environ['MESON_BUILD_ROOT']

    sep = sys.argv.index('--')
    sources = sys.argv[1:sep]
    command = sys.argv[sep + 1:]

    db_path = os.path.join(build_root, 'compile_commands.json')
    try:
        with open(db_path) as f:
            db = json.load(f)
    except FileNotFoundError:
        db = []

    sources_set = set(sources)
    db = [entry for entry in db if entry['file'] not in sources_set]

    for source in sources:
        db.append({
            'directory': build_root,
            'file': source,
            'arguments': [source if a == '@INPUT@' else a for a in command],
        })

    with open(db_path, 'w') as f:
        json.dump(db, f, indent=2)

    return 0


if __name__ == '__main__':
    sys.exit(main())
