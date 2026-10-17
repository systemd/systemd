#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Minimal io.systemd.ResourceProvider implementation serving files from a directory, for a single connection
# on stdin/stdout (i.e. for use with socket activation and Accept=yes). A resource named "trunc/<name>"
# announces the real size, but sends only half of the data.
#
# Usage: fake-resource-provider.py DIRECTORY

import json
import os
import sys


def reply(obj):
    os.write(1, json.dumps(obj).encode() + b'\0')


def main():
    root = sys.argv[1]

    buf = b''
    while b'\0' not in buf:
        c = os.read(0, 4096)
        if not c:
            return
        buf += c

    req = json.loads(buf.split(b'\0', 1)[0])
    name = (req.get('parameters') or {}).get('name', '')

    if req.get('method') != 'io.systemd.ResourceProvider.AcquireResource':
        reply({'error': 'org.varlink.service.MethodNotFound', 'parameters': {'method': req.get('method')}})
        return
    if not req.get('upgrade'):
        reply({'error': 'org.varlink.service.ExpectedUpgrade', 'parameters': {}})
        return

    trunc = name.startswith('trunc/')
    path = os.path.join(root, name[6:] if trunc else name)
    if not os.path.isfile(path):
        reply({'error': 'io.systemd.ResourceProvider.NoSuchResource', 'parameters': {}})
        return

    with open(path, 'rb') as f:
        data = f.read()

    reply({'parameters': {'size': len(data)}})
    if trunc:
        data = data[: len(data) // 2]
    while data:
        n = os.write(1, data)
        data = data[n:]


if __name__ == '__main__':
    main()
