#!/bin/bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -ex
set -o pipefail

systemd-analyze set-log-level debug
systemd-analyze set-log-target console

systemd-run --unit=one -p StandardOutput=file:/tmp/stdout -p StandardError=file:/tmp/stderr -p Type=exec sh -c 'echo x ; echo y >&2'
cmp /tmp/stdout <<EOF
x
EOF
cmp /tmp/stderr <<EOF
y
EOF

systemd-run --unit=two -p StandardOutput=file:/tmp/stdout -p StandardError=file:/tmp/stderr -p Type=exec sh -c 'echo z ; echo a >&2'
cmp /tmp/stdout <<EOF
z
EOF
cmp /tmp/stderr <<EOF
a
EOF

systemd-run --unit=three -p StandardOutput=append:/tmp/stdout -p StandardError=append:/tmp/stderr -p Type=exec sh -c 'echo b ; echo c >&2'
cmp /tmp/stdout <<EOF
z
b
EOF
cmp /tmp/stderr <<EOF
a
c
EOF

systemd-analyze set-log-level info

echo OK > /testok

exit 0
