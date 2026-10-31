#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Test StandardOutput=file:

systemd-run --wait --unit=TEST-23-UNIT-FILE-standard-output-one \
            -p StandardOutput=file:/tmp/stdout \
            -p StandardError=file:/tmp/stderr \
            -p Type=exec \
            bash -c 'echo x ; echo y >&2'
cmp /tmp/stdout <<EOF
x
EOF
cmp /tmp/stderr <<EOF
y
EOF

systemd-run --wait --unit=TEST-23-UNIT-FILE-standard-output-two \
            -p StandardOutput=file:/tmp/stdout \
            -p StandardError=file:/tmp/stderr \
            -p Type=exec \
            bash -c 'echo z ; echo a >&2'
cmp /tmp/stdout <<EOF
z
EOF
cmp /tmp/stderr <<EOF
a
EOF

systemd-run --wait --unit=TEST-23-UNIT-FILE-standard-output-three \
            -p StandardOutput=append:/tmp/stdout \
            -p StandardError=append:/tmp/stderr \
            -p Type=exec \
            bash -c 'echo b ; echo c >&2'
cmp /tmp/stdout <<EOF
z
b
EOF
cmp /tmp/stderr <<EOF
a
c
EOF

systemd-run --wait --unit=TEST-23-UNIT-FILE-standard-output-four \
            -p StandardOutput=truncate:/tmp/stdout \
            -p StandardError=truncate:/tmp/stderr \
            -p Type=exec \
            bash -c 'echo a ; echo b >&2'
cmp /tmp/stdout <<EOF
a
EOF
cmp /tmp/stderr <<EOF
b
EOF

# A dangling symlink as the output file is not followed when creating it: the unit must fail to start while
# setting up stdout, and the symlink target must not be created.
rm -f /tmp/stdout /tmp/stdout-target
ln -s /tmp/stdout-target /tmp/stdout
(! systemd-run --wait --unit=TEST-23-UNIT-FILE-standard-output-five \
            -p StandardOutput=file:/tmp/stdout \
            -p Type=exec \
            true)
[[ "$(systemctl show -P Result TEST-23-UNIT-FILE-standard-output-five.service)" == "exit-code" ]]
[[ "$(systemctl show -P ExecMainStatus TEST-23-UNIT-FILE-standard-output-five.service)" == "209" ]] # EXIT_STDOUT
systemctl reset-failed TEST-23-UNIT-FILE-standard-output-five.service
test ! -e /tmp/stdout-target
rm -f /tmp/stdout
