#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Minimal io.systemd.SysUpdate.Provider implementation serving component definitions from a JSON fixture
# file. The fixture is an object with a "targets" array (the reply to ListTargets()), and a "definitions"
# object mapping component names to the replies to DescribeTarget().
#
# Usage: fake-sysupdate-provider.py FIXTURE [SOCKET]
#
# Without SOCKET a single connection is served on stdin/stdout (i.e. for use with socket activation and
# Accept=yes), otherwise the specified AF_UNIX socket is bound and listened on.

import json
import os
import socket
import sys


def handle(fixture, req):
    method = req.get('method')
    params = req.get('parameters') or {}
    if method == 'io.systemd.SysUpdate.Provider.ListTargets':
        return {'parameters': {'targets': fixture['targets']}}
    if method == 'io.systemd.SysUpdate.Provider.DescribeTarget':
        tid = params.get('id') or {}
        d = fixture['definitions'].get(tid.get('name')) if tid.get('class') == 'component' else None
        if d is None:
            return {'error': 'io.systemd.SysUpdate.Provider.NoSuchTarget', 'parameters': {}}
        return {'parameters': d}
    return {'error': 'org.varlink.service.MethodNotFound', 'parameters': {'method': method}}


def serve(fixture, rfd, wfd):
    buf = b''
    while True:
        c = os.read(rfd, 4096)
        if not c:
            return
        buf += c
        while b'\0' in buf:
            msg, buf = buf.split(b'\0', 1)
            os.write(wfd, json.dumps(handle(fixture, json.loads(msg))).encode() + b'\0')


def main():
    with open(sys.argv[1]) as f:
        fixture = json.load(f)

    if len(sys.argv) <= 2:
        serve(fixture, 0, 1)
        return

    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(sys.argv[2])
    s.listen(16)
    while True:
        conn, _ = s.accept()
        if os.fork() == 0:
            serve(fixture, conn.fileno(), conn.fileno())
            os._exit(0)
        conn.close()


if __name__ == '__main__':
    main()
