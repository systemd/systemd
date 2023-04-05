#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

systemd-analyze log-level debug

test_directory() {
    local directory="$1"
    local path="$2"

    # cleanup for previous invocation
    for i in xxx xxx2 yyy zzz x:yz x:yz2; do
        rm -rf "${path:?}/${i}" "${path:?}/private/${i}"
    done

    # Set everything up without DynamicUser=1

    systemd-run --wait -p RuntimeDirectoryPreserve=yes -p DynamicUser=0 -p "${directory}"=zzz touch "${path}"/zzz/test
    systemd-run --wait -p RuntimeDirectoryPreserve=yes -p DynamicUser=0 -p "${directory}"=zzz test -f "${path}"/zzz/test
    systemd-run --wait -p RuntimeDirectoryPreserve=yes -p DynamicUser=0 -p "${directory}"=zzz -p TemporaryFileSystem="${path}" test -f "${path}"/zzz/test
    systemd-run --wait -p RuntimeDirectoryPreserve=yes -p DynamicUser=0 -p "${directory}"=zzz:yyy test -f "${path}"/yyy/test
    systemd-run --wait -p RuntimeDirectoryPreserve=yes -p DynamicUser=0 -p "${directory}=zzz:xxx zzz:xxx2" -p TemporaryFileSystem="${path}" bash -c "test -f ${path}/xxx/test && test -f ${path}/xxx2/test"
    systemd-run --wait -p RuntimeDirectoryPreserve=yes -p DynamicUser=0 -p "${directory}"=zzz:xxx -p TemporaryFileSystem="${path}":ro test -f "${path}"/xxx/test
    (! systemd-run --wait -p RuntimeDirectoryPreserve=yes -p DynamicUser=0 -p "${directory}"=zzz test -f "${path}"/zzz/test-missing)

    test -d "${path}"/zzz
    test ! -L "${path}"/zzz
    test ! -e "${path}"/private/zzz

    test ! -e "${path}"/xxx
    test ! -e "${path}"/private/xxx
    test ! -e "${path}"/xxx2
    test ! -e "${path}"/private/xxx2
    test -L "${path}"/yyy
    test ! -e "${path}"/private/yyy

    test -f "${path}"/zzz/test
    test ! -e "${path}"/zzz/test-missing

    # Convert to DynamicUser=1

    systemd-run --wait -p RuntimeDirectoryPreserve=yes -p DynamicUser=1 -p "${directory}"=zzz test -f "${path}"/zzz/test
    systemd-run --wait -p RuntimeDirectoryPreserve=yes -p DynamicUser=1 -p "${directory}"=zzz -p TemporaryFileSystem="${path}" test -f "${path}"/zzz/test
    systemd-run --wait -p RuntimeDirectoryPreserve=yes -p DynamicUser=1 -p "${directory}"=zzz:yyy test -f "${path}"/yyy/test
    systemd-run --wait -p RuntimeDirectoryPreserve=yes -p DynamicUser=1 -p "${directory}=zzz:xxx zzz:xxx2" \
                -p TemporaryFileSystem="${path}" -p EnvironmentFile=-/usr/lib/systemd/systemd-asan-env bash -c "test -f ${path}/xxx/test && test -f ${path}/xxx2/test"
    systemd-run --wait -p RuntimeDirectoryPreserve=yes -p DynamicUser=1 -p "${directory}"=zzz:xxx -p TemporaryFileSystem="${path}":ro test -f "${path}"/xxx/test
    (! systemd-run --wait -p RuntimeDirectoryPreserve=yes -p DynamicUser=1 -p "${directory}"=zzz test -f "${path}"/zzz/test-missing)

    test -L "${path}"/zzz
    test -d "${path}"/private/zzz

    test ! -e "${path}"/xxx
    test ! -e "${path}"/private/xxx
    test ! -e "${path}"/xxx2
    test ! -e "${path}"/private/xxx2
    test -L "${path}"/yyy # previous symlink is not removed
    test ! -e "${path}"/private/yyy

    test -f "${path}"/zzz/test
    test ! -e "${path}"/zzz/test-missing

    # Convert back

    systemd-run --wait -p RuntimeDirectoryPreserve=yes -p DynamicUser=0 -p "${directory}"=zzz test -f "${path}"/zzz/test
    systemd-run --wait -p RuntimeDirectoryPreserve=yes -p DynamicUser=0 -p "${directory}"=zzz -p TemporaryFileSystem="${path}" test -f "${path}"/zzz/test
    systemd-run --wait -p RuntimeDirectoryPreserve=yes -p DynamicUser=0 -p "${directory}"=zzz:yyy test -f "${path}"/yyy/test
    systemd-run --wait -p RuntimeDirectoryPreserve=yes -p DynamicUser=0 -p "${directory}"=zzz:xxx -p TemporaryFileSystem="${path}" test -f "${path}"/xxx/test
    systemd-run --wait -p RuntimeDirectoryPreserve=yes -p DynamicUser=0 -p "${directory}=zzz:xxx zzz:xxx2" -p TemporaryFileSystem="${path}" bash -c "test -f ${path}/xxx/test && test -f ${path}/xxx2/test"
    systemd-run --wait -p RuntimeDirectoryPreserve=yes -p DynamicUser=0 -p "${directory}"=zzz:xxx -p TemporaryFileSystem="${path}":ro test -f "${path}"/xxx/test
    (! systemd-run --wait -p RuntimeDirectoryPreserve=yes -p DynamicUser=0 -p "${directory}"=zzz test -f "${path}"/zzz/test-missing)

    test -d "${path}"/zzz
    test ! -L "${path}"/zzz
    test ! -e "${path}"/private/zzz

    test ! -e "${path}"/xxx
    test ! -e "${path}"/private/xxx
    test ! -e "${path}"/xxx2
    test ! -e "${path}"/private/xxx2
    test -L "${path}"/yyy
    test ! -e "${path}"/private/yyy

    test -f "${path}"/zzz/test
    test ! -e "${path}"/zzz/test-missing

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
    test ! -L "${path}"/zzz
    test ! -e "${path}"/private/zzz

    test ! -L "${path}"/x:yz
    test ! -L "${path}"/x:yz2
}

test_check_writable() {
    # cleanup for previous invocation
    for i in aaa quux waldo xxx; do
        rm -rf "/var/lib/$i" "/var/lib/private/$i"
    done

    cat >/run/systemd/system/testservice-34-check-writable.service <<\EOF
[Unit]
Description=Check writable directories when DynamicUser= with StateDirectory=

[Service]
# Relevant only for sanitizer runs
EnvironmentFile=-/usr/lib/systemd/systemd-asan-env

Type=oneshot
DynamicUser=yes
StateDirectory=waldo quux/pief aaa/bbb aaa aaa/ccc xxx/yyy:aaa/111 xxx:aaa/222 xxx/zzz:aaa/333

# Make sure that the state directories are really the only writable directory besides the obvious candidates
ExecStart=bash -c ' \
    set -eux; \
    set -o pipefail; \
    declare -a writable_dirs; \
    readarray -t writable_dirs < <(find / \( -path /var/tmp -o -path /tmp -o -path /proc -o -path /dev/mqueue -o -path /dev/shm -o \
                                              -path /sys/fs/bpf -o -path /dev/.lxc -o -path /sys/devices/system/cpu \) \
                                   -prune -o -type d -writable -print 2>/dev/null | sort -u); \
    [[ "$${#writable_dirs[@]}" == "8" ]]; \
    [[ "$${writable_dirs[0]}" == "/var/lib/private/aaa" ]]; \
    [[ "$${writable_dirs[1]}" == "/var/lib/private/aaa/bbb" ]]; \
    [[ "$${writable_dirs[2]}" == "/var/lib/private/aaa/ccc" ]]; \
    [[ "$${writable_dirs[3]}" == "/var/lib/private/quux/pief" ]]; \
    [[ "$${writable_dirs[4]}" == "/var/lib/private/waldo" ]]; \
    [[ "$${writable_dirs[5]}" == "/var/lib/private/xxx" ]]; \
    [[ "$${writable_dirs[6]}" == "/var/lib/private/xxx/yyy" ]]; \
    [[ "$${writable_dirs[7]}" == "/var/lib/private/xxx/zzz" ]]; \
'
EOF
    systemctl daemon-reload
    systemctl start testservice-34-check-writable.service
}

test_directory "StateDirectory" "/var/lib"
test_directory "RuntimeDirectory" "/run"
test_directory "CacheDirectory" "/var/cache"
test_directory "LogsDirectory" "/var/log"

test_check_writable

systemd-analyze log-level info

echo OK >/testok

exit 0
