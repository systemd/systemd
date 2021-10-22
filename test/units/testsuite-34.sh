#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

systemd-analyze log-level debug
systemd-analyze log-target console

# Set everything up without DynamicUser=1

systemd-run --wait -p DynamicUser=0 -p StateDirectory=zzz touch /var/lib/zzz/test
systemd-run --wait -p DynamicUser=0 -p StateDirectory=zzz test -f /var/lib/zzz/test
systemd-run --wait -p DynamicUser=0 -p StateDirectory=zzz -p TemporaryFileSystem=/var/lib test -f /var/lib/zzz/test
systemd-run --wait -p DynamicUser=0 -p StateDirectory=zzz:yyy test -f /var/lib/yyy/test
systemd-run --wait -p DynamicUser=0 -p StateDirectory=zzz:xxx -p TemporaryFileSystem=/var/lib test -f /var/lib/xxx/test
systemd-run --wait -p DynamicUser=0 -p StateDirectory=zzz:xxx -p TemporaryFileSystem=/var/lib:ro test -f /var/lib/xxx/test
systemd-run --wait -p DynamicUser=0 -p StateDirectory=zzz test -f /var/lib/zzz/test-missing \
    && { echo 'unexpected success'; exit 1; }

test -d /var/lib/zzz
test ! -L /var/lib/zzz
test ! -e /var/lib/private/zzz
test -f /var/lib/zzz/test
test ! -f /var/lib/zzz/test-missing

# Convert to DynamicUser=1

systemd-run --wait -p DynamicUser=1 -p StateDirectory=zzz test -f /var/lib/zzz/test
systemd-run --wait -p DynamicUser=1 -p StateDirectory=zzz -p TemporaryFileSystem=/var/lib test -f /var/lib/zzz/test
systemd-run --wait -p DynamicUser=1 -p StateDirectory=zzz:yyy test -f /var/lib/yyy/test
systemd-run --wait -p DynamicUser=1 -p StateDirectory=zzz:xxx -p TemporaryFileSystem=/var/lib test -f /var/lib/xxx/test
systemd-run --wait -p DynamicUser=1 -p StateDirectory=zzz:xxx -p TemporaryFileSystem=/var/lib:ro test -f /var/lib/xxx/test
systemd-run --wait -p DynamicUser=1 -p StateDirectory=zzz test -f /var/lib/zzz/test-missing \
    && { echo 'unexpected success'; exit 1; }

test -L /var/lib/zzz
test -L /var/lib/yyy
test -d /var/lib/private/zzz
test ! -L /var/lib/private/xxx
test ! -L /var/lib/xxx

test -f /var/lib/zzz/test
test ! -f /var/lib/zzz/test-missing

# Convert back

systemd-run --wait -p DynamicUser=0 -p StateDirectory=zzz test -f /var/lib/zzz/test
systemd-run --wait -p DynamicUser=0 -p StateDirectory=zzz -p TemporaryFileSystem=/var/lib test -f /var/lib/zzz/test
systemd-run --wait -p DynamicUser=0 -p StateDirectory=zzz:yyy test -f /var/lib/yyy/test
systemd-run --wait -p DynamicUser=0 -p StateDirectory=zzz:xxx -p TemporaryFileSystem=/var/lib test -f /var/lib/xxx/test
systemd-run --wait -p DynamicUser=0 -p "StateDirectory=zzz:xxx zzz:xxx2" -p TemporaryFileSystem=/var/lib bash -c "test -f /var/lib/xxx/test && test -f /var/lib/xxx2/test"
systemd-run --wait -p DynamicUser=0 -p StateDirectory=zzz:xxx -p TemporaryFileSystem=/var/lib:ro test -f /var/lib/xxx/test
systemd-run --wait -p DynamicUser=0 -p StateDirectory=zzz test -f /var/lib/zzz/test-missing \
    && { echo 'unexpected success'; exit 1; }

# Exercise the unit parsing paths too
cat >/run/systemd/system/testservice-34.service <<EOF
[Service]
Type=oneshot
TemporaryFileSystem=/var/lib
StateDirectory=zzz:x\:yz zzz:x\:yz2
ExecStart=test -f /var/lib/x:yz2/test
ExecStart=test -f /var/lib/x:yz/test
ExecStart=test -f /var/lib/zzz/test
EOF
systemctl daemon-reload
systemctl start --wait testservice-34.service

test -d /var/lib/zzz
test ! -L /var/lib/xxx
test ! -L /var/lib/xxx2
test ! -L /var/lib/private/xxx
test ! -L /var/lib/private/xxx2
test -L /var/lib/yyy
test ! -L /var/lib/zzz
test ! -e /var/lib/private/zzz
test -f /var/lib/zzz/test
test ! -f /var/lib/zzz/test-missing
test ! -L /var/lib/x:yz
test ! -L /var/lib/x:yz2

systemd-analyze log-level info

echo OK >/testok

exit 0
