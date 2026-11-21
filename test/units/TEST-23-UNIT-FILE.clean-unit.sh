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
    systemctl stop test-clean-connection.socket test-clean-runtime.service
    rm -f /run/systemd/system/test-clean-connection{.socket,@.service} \
          /run/systemd/system/test-clean-runtime.service /run/systemd/system/test-clean-template@.service
    rm -fr /var/lib/test-clean-connection
}

trap at_exit EXIT

unit_in_memory() {
    # GetUnit, unlike LoadUnit or systemctl show, never loads the unit.
    busctl --quiet call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager GetUnit s "$1"
}

wait_for_gc() {
    for _ in {1..50}; do
        if ! unit_in_memory "$1"; then
            return 0
        fi
        sleep .1
    done
    return 1
}

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

# Merely having directory settings must not pin the unit.
systemctl clean test-service --what=cache
wait_for_gc test-service.service

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

unit_in_memory test-service.service
rm /run/systemd/system/test-service.service

test -d /etc/test-service
test -d /run/test-service
test -d /var/lib/test-service
test -d /var/cache/test-service
test -d /var/log/test-service

systemctl clean test-service --what=configuration

systemctl daemon-reload
unit_in_memory test-service.service
test "$(systemctl show -P LoadState test-service)" = not-found
(! systemctl start test-service)

test ! -e /etc/test-service
test -d /run/test-service
test -d /var/lib/test-service
test -d /var/cache/test-service
test -d /var/log/test-service

systemctl clean test-service

test "$(systemctl show -P Slice test-service)" = system.slice
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

test "$(systemctl show -P CanClean test-service)" = state
# A new directory at a path already cleaned no longer belongs to the removed unit.
mkdir /var/cache/test-service
systemctl clean test-service --what=all
wait_for_gc test-service.service
rmdir /var/cache/test-service

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

# A dangling symlink is itself a resource to clean, even if its private target is already gone.
rmdir /var/lib/private/test-service
test -L /var/lib/test-service
test ! -e /var/lib/test-service
systemctl daemon-reload
unit_in_memory test-service.service
systemctl clean test-service --what=all
wait_for_gc test-service.service

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

rm /run/systemd/system/tmp-hoge.mount
systemctl daemon-reload

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

# RuntimeDirectoryPreserve=restart preserves the private directory across a restart, but must remove
# both the private directory and its public symlink on the final stop.
systemd-run -u test-clean-runtime -p Type=exec -p DynamicUser=yes \
    -p RuntimeDirectory=test-clean-runtime -p RuntimeDirectoryPreserve=restart sleep infinity
test -L /run/test-clean-runtime
touch /run/test-clean-runtime/marker
systemctl restart test-clean-runtime.service
test -f /run/test-clean-runtime/marker
systemctl stop test-clean-runtime.service
wait_for_gc test-clean-runtime.service
test ! -L /run/test-clean-runtime
test ! -e /run/private/test-clean-runtime

# Reuse the transient name. If its fragment disappears while it is still running, a replacement on
# disk must be read as a regular unit file, not treated as another transient fragment.
systemd-run -u test-clean-runtime -p Type=exec -p StateDirectory=test-clean-connection sleep infinity
rm /run/systemd/transient/test-clean-runtime.service
systemctl daemon-reload
cat >/run/systemd/system/test-clean-runtime.service <<EOF
[Service]
ExecStart=true
EOF
test "$(systemctl show -P FragmentPath test-clean-runtime.service)" = /run/systemd/system/test-clean-runtime.service
systemctl stop test-clean-runtime.service
rm /run/systemd/system/test-clean-runtime.service

# Each connection uses a fresh service name but the same state directory. Reload while the instance
# is running to check that it remains collectible even after its socket reference is dropped.
cat >/run/systemd/system/test-clean-connection.socket <<EOF
[Socket]
ListenStream=/run/test-clean-connection.sock
Accept=yes
RemoveOnStop=yes
EOF
cat >/run/systemd/system/test-clean-connection@.service <<'EOF'
[Service]
StandardOutput=socket
StateDirectory=test-clean-connection
ExecStart=sh -ec 'systemctl daemon-reload; echo %n'
EOF
cat >/run/systemd/system/test-clean-template@.service <<EOF
[Service]
Type=oneshot
StateDirectory=test-clean-connection/%i
ExecStart=true
EOF
systemctl daemon-reload
systemctl start test-clean-connection.socket
instance=$(socat -u UNIX-CONNECT:/run/test-clean-connection.sock -)
[[ "$instance" == test-clean-connection@*.service ]]
wait_for_gc "$instance"
test -d /var/lib/test-clean-connection

# A manually started instance is collectible even if it has its own state directory. Its template
# is still on disk, so clean can load it again on demand.
systemctl start test-clean-template@manual.service
wait_for_gc test-clean-template@manual.service
test -d /var/lib/test-clean-connection/manual
systemctl clean --what=state test-clean-template@manual.service
test ! -e /var/lib/test-clean-connection/manual
