#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

systemd-analyze log-level debug
systemd-analyze log-target console

function test_directory() {
    local directory="$1"
    local path="$2"

    # Set everything up without DynamicUser=1

    systemd-run --wait -p RuntimeDirectoryPreserve=yes -p DynamicUser=0 -p "${directory}"=zzz touch "${path}"/zzz/test
    systemd-run --wait -p RuntimeDirectoryPreserve=yes -p DynamicUser=0 -p "${directory}"=zzz test -f "${path}"/zzz/test
    systemd-run --wait -p RuntimeDirectoryPreserve=yes -p DynamicUser=0 -p "${directory}"=zzz -p TemporaryFileSystem="${path}" test -f "${path}"/zzz/test
    systemd-run --wait -p RuntimeDirectoryPreserve=yes -p DynamicUser=0 -p "${directory}"=zzz:yyy test -f "${path}"/yyy/test
    systemd-run --wait -p RuntimeDirectoryPreserve=yes -p DynamicUser=0 -p "${directory}"=zzz:xxx -p TemporaryFileSystem="${path}" test -f "${path}"/xxx/test
    systemd-run --wait -p RuntimeDirectoryPreserve=yes -p DynamicUser=0 -p "${directory}"=zzz:xxx -p TemporaryFileSystem="${path}":ro test -f "${path}"/xxx/test
    systemd-run --wait -p RuntimeDirectoryPreserve=yes -p DynamicUser=0 -p "${directory}"=zzz test -f "${path}"/zzz/test-missing \
        && { echo 'unexpected success'; exit 1; }

    test -d "${path}"/zzz
    test ! -L "${path}"/zzz
    test ! -e "${path}"/private/zzz
    test -f "${path}"/zzz/test
    test ! -f "${path}"/zzz/test-missing

    # Convert to DynamicUser=1

    systemd-run --wait -p RuntimeDirectoryPreserve=yes -p DynamicUser=1 -p "${directory}"=zzz test -f "${path}"/zzz/test
    systemd-run --wait -p RuntimeDirectoryPreserve=yes -p DynamicUser=1 -p "${directory}"=zzz -p TemporaryFileSystem="${path}" test -f "${path}"/zzz/test
    systemd-run --wait -p RuntimeDirectoryPreserve=yes -p DynamicUser=1 -p "${directory}"=zzz:yyy test -f "${path}"/yyy/test
    systemd-run --wait -p RuntimeDirectoryPreserve=yes -p DynamicUser=1 -p "${directory}"=zzz:xxx -p TemporaryFileSystem="${path}" test -f "${path}"/xxx/test
    systemd-run --wait -p RuntimeDirectoryPreserve=yes -p DynamicUser=1 -p "${directory}"=zzz:xxx -p TemporaryFileSystem="${path}":ro test -f "${path}"/xxx/test
    systemd-run --wait -p RuntimeDirectoryPreserve=yes -p DynamicUser=1 -p "${directory}"=zzz test -f "${path}"/zzz/test-missing \
        && { echo 'unexpected success'; exit 1; }

    test -L "${path}"/zzz
    test -L "${path}"/yyy
    test -d "${path}"/private/zzz
    test ! -L "${path}"/private/xxx
    test ! -L "${path}"/xxx

    test -f "${path}"/zzz/test
    test ! -f "${path}"/zzz/test-missing

    # Convert back

    systemd-run --wait -p RuntimeDirectoryPreserve=yes -p DynamicUser=0 -p "${directory}"=zzz test -f "${path}"/zzz/test
    systemd-run --wait -p RuntimeDirectoryPreserve=yes -p DynamicUser=0 -p "${directory}"=zzz -p TemporaryFileSystem="${path}" test -f "${path}"/zzz/test
    systemd-run --wait -p RuntimeDirectoryPreserve=yes -p DynamicUser=0 -p "${directory}"=zzz:yyy test -f "${path}"/yyy/test
    systemd-run --wait -p RuntimeDirectoryPreserve=yes -p DynamicUser=0 -p "${directory}"=zzz:xxx -p TemporaryFileSystem="${path}" test -f "${path}"/xxx/test
    systemd-run --wait -p RuntimeDirectoryPreserve=yes -p DynamicUser=0 -p "${directory}=zzz:xxx zzz:xxx2" -p TemporaryFileSystem="${path}" bash -c "test -f ${path}/xxx/test && test -f ${path}/xxx2/test"
    systemd-run --wait -p RuntimeDirectoryPreserve=yes -p DynamicUser=0 -p "${directory}"=zzz:xxx -p TemporaryFileSystem="${path}":ro test -f "${path}"/xxx/test
    systemd-run --wait -p RuntimeDirectoryPreserve=yes -p DynamicUser=0 -p "${directory}"=zzz test -f "${path}"/zzz/test-missing \
        && { echo 'unexpected success'; exit 1; }

    # Exercise the unit parsing paths too
    cat >/run/systemd/system/testservice-34.service <<EOF
[Service]
Type=oneshot
TemporaryFileSystem=${path}
RuntimeDirectoryPreserve=yes
${directory}=zzz:x\:yz zzz:x\:yz2
ExecStart=test -f ${path}/x:yz2/test
ExecStart=test -f ${path}/x:yz/test
ExecStart=test -f ${path}/zzz/test
EOF
    systemctl daemon-reload
    systemctl start --wait testservice-34.service

    test -d "${path}"/zzz
    test ! -L "${path}"/xxx
    test ! -L "${path}"/xxx2
    test ! -L "${path}"/private/xxx
    test ! -L "${path}"/private/xxx2
    test -L "${path}"/yyy
    test ! -L "${path}"/zzz
    test ! -e "${path}"/private/zzz
    test -f "${path}"/zzz/test
    test ! -f "${path}"/zzz/test-missing
    test ! -L "${path}"/x:yz
    test ! -L "${path}"/x:yz2
}

test_directory "StateDirectory" "/var/lib"
test_directory "RuntimeDirectory" "/run"
test_directory "CacheDirectory" "/var/cache"
test_directory "LogsDirectory" "/var/log"

systemd-analyze log-level info

echo OK >/testok

exit 0
