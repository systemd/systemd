#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import json
import os
import sys


def main() -> int:
    build_root = os.environ['MESON_BUILD_ROOT']
    source = sys.argv[1]

    stem = os.path.basename(source)
    while '.' in stem:
        stem = os.path.splitext(stem)[0]
    output = f'{stem}.bpf.unstripped.o'

    arguments = [
        source if a == '@INPUT@' else
        output if a == '@OUTPUT@' else a
        for a in sys.argv[2:]
    ]

    db_path = os.path.join(build_root, 'compile_commands.json')
    try:
        with open(db_path) as f:
            db = json.load(f)
    except FileNotFoundError:
        db = []

    seen = {entry['file']: entry for entry in db}
    seen[source] = {
        'directory': build_root,
        'file': source,
        'arguments': arguments,
    }

    with open(db_path, 'w') as f:
        json.dump(list(seen.values()), f, indent=2)

    return 0


if __name__ == '__main__':
    sys.exit(main())
