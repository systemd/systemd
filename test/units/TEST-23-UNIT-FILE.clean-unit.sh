#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -eux
set -o pipefail

# Test unit configuration/state/cache/log/runtime data cleanup

at_exit() {
    set +e

    rm -fr /{etc,run,var/lib,var/cache,var/log}/test-service
    rm -fr /{etc,run,var/lib,var/cache,var/log}/private/test-service
    rm -fr /{etc,run,var/lib,var/cache,var/log}/hoge
    rm -fr /{etc,run,var/lib,var/cache,var/log}/test-socket
}

trap at_exit EXIT

cat >/run/systemd/system/test-service.service <<EOF
[Service]
ConfigurationDirectory=test-service
RuntimeDirectory=test-service
StateDirectory=test-service
CacheDirectory=test-service
LogsDirectory=test-service
RuntimeDirectoryPreserve=yes
ExecStart=sleep infinity
Type=exec
EOF

systemctl daemon-reload

test ! -e /etc/test-service
test ! -e /run/test-service
test ! -e /var/lib/test-service
test ! -e /var/cache/test-service
test ! -e /var/log/test-service

systemctl start test-service

test -d /etc/test-service
test -d /run/test-service
test -d /var/lib/test-service
test -d /var/cache/test-service
test -d /var/log/test-service

(! systemctl clean test-service)

systemctl stop test-service

test -d /etc/test-service
test -d /run/test-service
test -d /var/lib/test-service
test -d /var/cache/test-service
test -d /var/log/test-service

systemctl clean test-service --what=configuration

test ! -e /etc/test-service
test -d /run/test-service
test -d /var/lib/test-service
test -d /var/cache/test-service
test -d /var/log/test-service

systemctl clean test-service

test ! -e /etc/test-service
test ! -e /run/test-service
test -d /var/lib/test-service
test ! -e /var/cache/test-service
test -d /var/log/test-service

systemctl clean test-service --what=logs

test ! -e /etc/test-service
test ! -e /run/test-service
test -d /var/lib/test-service
test ! -e /var/cache/test-service
test ! -e /var/log/test-service

systemctl clean test-service --what=all

test ! -e /etc/test-service
test ! -e /run/test-service
test ! -e /var/lib/test-service
test ! -e /var/cache/test-service
test ! -e /var/log/test-service

cat >/run/systemd/system/test-service.service <<EOF
[Service]
DynamicUser=yes
ConfigurationDirectory=test-service
RuntimeDirectory=test-service
StateDirectory=test-service
CacheDirectory=test-service
LogsDirectory=test-service
RuntimeDirectoryPreserve=yes
ExecStart=sleep infinity
Type=exec
EOF

systemctl daemon-reload

test ! -e /etc/test-service
test ! -e /run/test-service
test ! -e /var/lib/test-service
test ! -e /var/cache/test-service
test ! -e /var/log/test-service

systemctl restart test-service

test -d /etc/test-service
test -d /run/private/test-service
test -d /var/lib/private/test-service
test -d /var/cache/private/test-service
test -d /var/log/private/test-service
test -L /run/test-service
test -L /var/lib/test-service
test -L /var/cache/test-service
test -L /var/log/test-service

(! systemctl clean test-service)

systemctl stop test-service

test -d /etc/test-service
test -d /run/private/test-service
test -d /var/lib/private/test-service
test -d /var/cache/private/test-service
test -d /var/log/private/test-service
test -L /run/test-service
test -L /var/lib/test-service
test -L /var/cache/test-service
test -L /var/log/test-service

systemctl clean test-service --what=configuration

test ! -d /etc/test-service
test -d /run/private/test-service
test -d /var/lib/private/test-service
test -d /var/cache/private/test-service
test -d /var/log/private/test-service
test -L /run/test-service
test -L /var/lib/test-service
test -L /var/cache/test-service
test -L /var/log/test-service

systemctl clean test-service

test ! -d /etc/test-service
test ! -d /run/private/test-service
test -d /var/lib/private/test-service
test ! -d /var/cache/private/test-service
test -d /var/log/private/test-service
test ! -L /run/test-service
test -L /var/lib/test-service
test ! -L /var/cache/test-service
test -L /var/log/test-service

systemctl clean test-service --what=logs

test ! -d /etc/test-service
test ! -d /run/private/test-service
test -d /var/lib/private/test-service
test ! -d /var/cache/private/test-service
test ! -d /var/log/private/test-service
test ! -L /run/test-service
test -L /var/lib/test-service
test ! -L /var/cache/test-service
test ! -L /var/log/test-service

systemctl clean test-service --what=all

test ! -d /etc/test-service
test ! -d /run/private/test-service
test ! -d /var/lib/private/test-service
test ! -d /var/cache/private/test-service
test ! -d /var/log/private/test-service
test ! -L /run/test-service
test ! -L /var/lib/test-service
test ! -L /var/cache/test-service
test ! -L /var/log/test-service

cat >/run/systemd/system/tmp-hoge.mount <<EOF
[Mount]
What=tmpfs
Type=tmpfs
ConfigurationDirectory=hoge
RuntimeDirectory=hoge
StateDirectory=hoge
CacheDirectory=hoge
LogsDirectory=hoge
EOF

systemctl daemon-reload

test ! -e /etc/hoge
test ! -e /run/hoge
test ! -e /var/lib/hoge
test ! -e /var/cache/hoge
test ! -e /var/log/hoge

systemctl start tmp-hoge.mount

test -d /etc/hoge
test -d /run/hoge
test -d /var/lib/hoge
test -d /var/cache/hoge
test -d /var/log/hoge

(! systemctl clean tmp-hoge.mount)

test -d /etc/hoge
test -d /run/hoge
test -d /var/lib/hoge
test -d /var/cache/hoge
test -d /var/log/hoge

systemctl stop tmp-hoge.mount

test -d /etc/hoge
test ! -d /run/hoge
test -d /var/lib/hoge
test -d /var/cache/hoge
test -d /var/log/hoge

systemctl clean tmp-hoge.mount --what=configuration

test ! -d /etc/hoge
test ! -d /run/hoge
test -d /var/lib/hoge
test -d /var/cache/hoge
test -d /var/log/hoge

systemctl clean tmp-hoge.mount

test ! -d /etc/hoge
test ! -d /run/hoge
test -d /var/lib/hoge
test ! -d /var/cache/hoge
test -d /var/log/hoge

systemctl clean tmp-hoge.mount --what=logs

test ! -d /etc/hoge
test ! -d /run/hoge
test -d /var/lib/hoge
test ! -d /var/cache/hoge
test ! -d /var/log/hoge

systemctl clean tmp-hoge.mount --what=all

test ! -d /etc/hoge
test ! -d /run/hoge
test ! -d /var/lib/hoge
test ! -d /var/cache/hoge
test ! -d /var/log/hoge

cat >/run/systemd/system/test-service.socket <<EOF
[Socket]
ListenSequentialPacket=/run/test-service.socket
RemoveOnStop=yes
ExecStartPre=true
ConfigurationDirectory=test-socket
RuntimeDirectory=test-socket
StateDirectory=test-socket
CacheDirectory=test-socket
LogsDirectory=test-socket
EOF

systemctl daemon-reload

test ! -e /etc/test-socket
test ! -e /run/test-socket
test ! -e /var/lib/test-socket
test ! -e /var/cache/test-socket
test ! -e /var/log/test-socket

systemctl start test-service.socket

test -d /etc/test-socket
test -d /run/test-socket
test -d /var/lib/test-socket
test -d /var/cache/test-socket
test -d /var/log/test-socket

(! systemctl clean test-service.socket)

systemctl stop test-service.socket

test -d /etc/test-socket
test ! -d /run/test-socket
test -d /var/lib/test-socket
test -d /var/cache/test-socket
test -d /var/log/test-socket

systemctl clean test-service.socket --what=configuration

test ! -e /etc/test-socket
test ! -d /run/test-socket
test -d /var/lib/test-socket
test -d /var/cache/test-socket
test -d /var/log/test-socket

systemctl clean test-service.socket

test ! -e /etc/test-socket
test ! -e /run/test-socket
test -d /var/lib/test-socket
test ! -e /var/cache/test-socket
test -d /var/log/test-socket

systemctl clean test-service.socket --what=logs

test ! -e /etc/test-socket
test ! -e /run/test-socket
test -d /var/lib/test-socket
test ! -e /var/cache/test-socket
test ! -e /var/log/test-socket

systemctl clean test-service.socket --what=all

test ! -e /etc/test-socket
test ! -e /run/test-socket
test ! -e /var/lib/test-socket
test ! -e /var/cache/test-socket
test ! -e /var/log/test-socket
