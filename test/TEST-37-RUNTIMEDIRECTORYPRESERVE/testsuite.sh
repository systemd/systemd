#!/bin/bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -ex
set -o pipefail

systemd-mount -p RuntimeDirectory=hoge -p RuntimeDirectoryPreserve=yes -t tmpfs tmpfs /tmp/aaa

touch /run/hoge/foo
touch /tmp/aaa/bbb

systemctl restart tmp-aaa.mount

test -e /run/hoge/foo
! test -e /tmp/aaa/bbb

echo OK > /testok

exit 0
