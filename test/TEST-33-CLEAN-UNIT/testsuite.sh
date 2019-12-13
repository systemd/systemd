#!/bin/bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -ex
set -o pipefail

cat > /etc/systemd/system/testservice.service <<EOF
[Service]
ConfigurationDirectory=testservice
RuntimeDirectory=testservice
StateDirectory=testservice
CacheDirectory=testservice
LogsDirectory=testservice
RuntimeDirectoryPreserve=yes
ExecStart=/bin/sleep infinity
Type=exec
EOF

systemctl daemon-reload

! test -e /etc/testservice
! test -e /run/testservice
! test -e /var/lib/testservice
! test -e /var/cache/testservice
! test -e /var/log/testservice

systemctl start testservice

test -d /etc/testservice
test -d /run/testservice
test -d /var/lib/testservice
test -d /var/cache/testservice
test -d /var/log/testservice

! systemctl clean testservice

systemctl stop testservice

test -d /etc/testservice
test -d /run/testservice
test -d /var/lib/testservice
test -d /var/cache/testservice
test -d /var/log/testservice

systemctl clean testservice --what=configuration

! test -e /etc/testservice
test -d /run/testservice
test -d /var/lib/testservice
test -d /var/cache/testservice
test -d /var/log/testservice

systemctl clean testservice

! test -e /etc/testservice
! test -e /run/testservice
test -d /var/lib/testservice
! test -e /var/cache/testservice
test -d /var/log/testservice

systemctl clean testservice --what=logs

! test -e /etc/testservice
! test -e /run/testservice
test -d /var/lib/testservice
! test -e /var/cache/testservice
! test -e /var/log/testservice

systemctl clean testservice --what=all

! test -e /etc/testservice
! test -e /run/testservice
! test -e /var/lib/testservice
! test -e /var/cache/testservice
! test -e /var/log/testservice

cat > /etc/systemd/system/testservice.service <<EOF
[Service]
DynamicUser=yes
ConfigurationDirectory=testservice
RuntimeDirectory=testservice
StateDirectory=testservice
CacheDirectory=testservice
LogsDirectory=testservice
RuntimeDirectoryPreserve=yes
ExecStart=/bin/sleep infinity
Type=exec
EOF

systemctl daemon-reload

! test -e /etc/testservice
! test -e /run/testservice
! test -e /var/lib/testservice
! test -e /var/cache/testservice
! test -e /var/log/testservice

systemctl restart testservice

test -d /etc/testservice
test -d /run/private/testservice
test -d /var/lib/private/testservice
test -d /var/cache/private/testservice
test -d /var/log/private/testservice
test -L /run/testservice
test -L /var/lib/testservice
test -L /var/cache/testservice
test -L /var/log/testservice

! systemctl clean testservice

systemctl stop testservice

test -d /etc/testservice
test -d /run/private/testservice
test -d /var/lib/private/testservice
test -d /var/cache/private/testservice
test -d /var/log/private/testservice
test -L /run/testservice
test -L /var/lib/testservice
test -L /var/cache/testservice
test -L /var/log/testservice

systemctl clean testservice --what=configuration

! test -d /etc/testservice
test -d /run/private/testservice
test -d /var/lib/private/testservice
test -d /var/cache/private/testservice
test -d /var/log/private/testservice
test -L /run/testservice
test -L /var/lib/testservice
test -L /var/cache/testservice
test -L /var/log/testservice

systemctl clean testservice

! test -d /etc/testservice
! test -d /run/private/testservice
test -d /var/lib/private/testservice
! test -d /var/cache/private/testservice
test -d /var/log/private/testservice
! test -L /run/testservice
test -L /var/lib/testservice
! test -L /var/cache/testservice
test -L /var/log/testservice

systemctl clean testservice --what=logs

! test -d /etc/testservice
! test -d /run/private/testservice
test -d /var/lib/private/testservice
! test -d /var/cache/private/testservice
! test -d /var/log/private/testservice
! test -L /run/testservice
test -L /var/lib/testservice
! test -L /var/cache/testservice
! test -L /var/log/testservice

systemctl clean testservice --what=all

! test -d /etc/testservice
! test -d /run/private/testservice
! test -d /var/lib/private/testservice
! test -d /var/cache/private/testservice
! test -d /var/log/private/testservice
! test -L /run/testservice
! test -L /var/lib/testservice
! test -L /var/cache/testservice
! test -L /var/log/testservice

cat > /etc/systemd/system/tmp-hoge.mount <<EOF
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

! test -e /etc/hoge
! test -e /run/hoge
! test -e /var/lib/hoge
! test -e /var/cache/hoge
! test -e /var/log/hoge

systemctl start tmp-hoge.mount

test -d /etc/hoge
test -d /run/hoge
test -d /var/lib/hoge
test -d /var/cache/hoge
test -d /var/log/hoge

! systemctl clean tmp-hoge.mount

test -d /etc/hoge
test -d /run/hoge
test -d /var/lib/hoge
test -d /var/cache/hoge
test -d /var/log/hoge

systemctl stop tmp-hoge.mount

test -d /etc/hoge
! test -d /run/hoge
test -d /var/lib/hoge
test -d /var/cache/hoge
test -d /var/log/hoge

systemctl clean tmp-hoge.mount --what=configuration

! test -d /etc/hoge
! test -d /run/hoge
test -d /var/lib/hoge
test -d /var/cache/hoge
test -d /var/log/hoge

systemctl clean tmp-hoge.mount

! test -d /etc/hoge
! test -d /run/hoge
test -d /var/lib/hoge
! test -d /var/cache/hoge
test -d /var/log/hoge

systemctl clean tmp-hoge.mount --what=logs

! test -d /etc/hoge
! test -d /run/hoge
test -d /var/lib/hoge
! test -d /var/cache/hoge
! test -d /var/log/hoge

systemctl clean tmp-hoge.mount --what=all

! test -d /etc/hoge
! test -d /run/hoge
! test -d /var/lib/hoge
! test -d /var/cache/hoge
! test -d /var/log/hoge

cat > /etc/systemd/system/testservice.socket <<EOF
[Socket]
ListenSequentialPacket=/run/testservice.socket
RemoveOnStop=yes
ExecStartPre=true
ConfigurationDirectory=testsocket
RuntimeDirectory=testsocket
StateDirectory=testsocket
CacheDirectory=testsocket
LogsDirectory=testsocket
EOF

systemctl daemon-reload

! test -e /etc/testsocket
! test -e /run/testsocket
! test -e /var/lib/testsocket
! test -e /var/cache/testsocket
! test -e /var/log/testsocket

systemctl start testservice.socket

test -d /etc/testsocket
! test -d /run/testsocket
test -d /var/lib/testsocket
test -d /var/cache/testsocket
test -d /var/log/testsocket

! systemctl clean testservice.socket

systemctl stop testservice.socket

test -d /etc/testsocket
! test -d /run/testsocket
test -d /var/lib/testsocket
test -d /var/cache/testsocket
test -d /var/log/testsocket

systemctl clean testservice.socket --what=configuration

! test -e /etc/testsocket
! test -d /run/testsocket
test -d /var/lib/testsocket
test -d /var/cache/testsocket
test -d /var/log/testsocket

systemctl clean testservice.socket

! test -e /etc/testsocket
! test -e /run/testsocket
test -d /var/lib/testsocket
! test -e /var/cache/testsocket
test -d /var/log/testsocket

systemctl clean testservice.socket --what=logs

! test -e /etc/testsocket
! test -e /run/testsocket
test -d /var/lib/testsocket
! test -e /var/cache/testsocket
! test -e /var/log/testsocket

systemctl clean testservice.socket --what=all

! test -e /etc/testsocket
! test -e /run/testsocket
! test -e /var/lib/testsocket
! test -e /var/cache/testsocket
! test -e /var/log/testsocket

echo OK > /testok

exit 0
