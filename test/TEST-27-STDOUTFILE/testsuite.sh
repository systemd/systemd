#!/bin/bash
set -ex
set -o pipefail

systemd-analyze log-level debug
systemd-analyze log-target console

systemd-run --wait --unit=one \
            -p StandardOutput=file:/tmp/stdout \
            -p StandardError=file:/tmp/stderr \
            -p Type=exec \
            sh -c 'echo x ; echo y >&2'
cmp /tmp/stdout <<EOF
x
EOF
cmp /tmp/stderr <<EOF
y
EOF

systemd-run --wait --unit=two \
            -p StandardOutput=file:/tmp/stdout \
            -p StandardError=file:/tmp/stderr \
            -p Type=exec \
            sh -c 'echo z ; echo a >&2'
cmp /tmp/stdout <<EOF
z
EOF
cmp /tmp/stderr <<EOF
a
EOF

systemd-run --wait --unit=three \
            -p StandardOutput=append:/tmp/stdout \
            -p StandardError=append:/tmp/stderr \
            -p Type=exec \
            sh -c 'echo b ; echo c >&2'
cmp /tmp/stdout <<EOF
z
b
EOF
cmp /tmp/stderr <<EOF
a
c
EOF

systemd-analyze log-level info

echo OK > /testok

exit 0
