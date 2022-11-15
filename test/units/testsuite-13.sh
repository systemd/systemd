#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

export SYSTEMD_LOG_LEVEL=debug
export SYSTEMD_LOG_TARGET=journal

# check cgroup-v2
is_v2_supported=no
mkdir -p /tmp/cgroup2
if mount -t cgroup2 cgroup2 /tmp/cgroup2; then
    is_v2_supported=yes
    umount /tmp/cgroup2
fi
rmdir /tmp/cgroup2

# check cgroup namespaces
is_cgns_supported=no
if [[ -f /proc/1/ns/cgroup ]]; then
    is_cgns_supported=yes
fi

is_user_ns_supported=no
# On some systems (e.g. CentOS 7) the default limit for user namespaces
# is set to 0, which causes the following unshare syscall to fail, even
# with enabled user namespaces support. By setting this value explicitly
# we can ensure the user namespaces support to be detected correctly.
sysctl -w user.max_user_namespaces=10000
if unshare -U sh -c :; then
    is_user_ns_supported=yes
fi

function check_bind_tmp_path {
    # https://github.com/systemd/systemd/issues/4789
    local _root="/var/lib/machines/testsuite-13.bind-tmp-path"
    rm -rf "$_root"
    /usr/lib/systemd/tests/testdata/create-busybox-container "$_root"
    : >/tmp/bind
    systemd-nspawn --register=no -D "$_root" --bind=/tmp/bind /bin/sh -c 'test -e /tmp/bind'
}

function check_norbind {
    # https://github.com/systemd/systemd/issues/13170
    local _root="/var/lib/machines/testsuite-13.norbind-path"
    rm -rf "$_root"
    mkdir -p /tmp/binddir/subdir
    echo -n "outer" >/tmp/binddir/subdir/file
    mount -t tmpfs tmpfs /tmp/binddir/subdir
    echo -n "inner" >/tmp/binddir/subdir/file
    /usr/lib/systemd/tests/testdata/create-busybox-container "$_root"
    systemd-nspawn --register=no -D "$_root" --bind=/tmp/binddir:/mnt:norbind /bin/sh -c 'CONTENT=$(cat /mnt/subdir/file); if [[ $CONTENT != "outer" ]]; then echo "*** unexpected content: $CONTENT"; return 1; fi'
}

function check_rootidmap {
    local _owner=1000
    local _root="/var/lib/machines/testsuite-13.rootidmap-path"
    local _command
    rm -rf "$_root"

    # Create ext4 image, as ext4 supports idmapped-mounts.
    dd if=/dev/zero of=/tmp/ext4.img bs=4k count=2048
    mkfs.ext4 /tmp/ext4.img
    mkdir -p /tmp/rootidmapdir
    mount /tmp/ext4.img /tmp/rootidmapdir

    touch /tmp/rootidmapdir/file
    chown -R $_owner:$_owner /tmp/rootidmapdir

    /usr/lib/systemd/tests/testdata/create-busybox-container "$_root"
    _command='PERMISSIONS=$(stat -c "%u:%g" /mnt/file); if [[ $PERMISSIONS != "0:0" ]]; then echo "*** wrong permissions: $PERMISSIONS"; return 1; fi; touch /mnt/other_file'
    if ! SYSTEMD_LOG_TARGET=console systemd-nspawn \
            --register=no -D "$_root" \
            --bind=/tmp/rootidmapdir:/mnt:rootidmap \
            /bin/sh -c "$_command" |& tee nspawn.out; then
        if grep -q "Failed to map ids for bind mount.*: Function not implemented" nspawn.out; then
            echo "idmapped mounts are not supported, skipping the test..."
            return 0
        fi

        return 1
    fi

    PERMISSIONS=$(stat -c "%u:%g" /tmp/rootidmapdir/other_file)
    if [[ $PERMISSIONS != "$_owner:$_owner" ]]; then
        echo "*** wrong permissions: $PERMISSIONS"
        [[ "$is_user_ns_supported" = "yes" ]] && return 1
    fi
}

function check_notification_socket {
    # https://github.com/systemd/systemd/issues/4944
    local _cmd='echo a | $(busybox which nc) -U -u -w 1 /run/host/notify'
    # /testsuite-13.nc-container is prepared by test.sh
    systemd-nspawn --register=no -D /testsuite-13.nc-container /bin/sh -x -c "$_cmd"
    systemd-nspawn --register=no -D /testsuite-13.nc-container -U /bin/sh -x -c "$_cmd"
}

function check_os_release {
    local _cmd='. /tmp/os-release
if [ -n "${ID:+set}" ] && [ "${ID}" != "${container_host_id}" ]; then exit 1; fi
if [ -n "${VERSION_ID:+set}" ] && [ "${VERSION_ID}" != "${container_host_version_id}" ]; then exit 1; fi
if [ -n "${BUILD_ID:+set}" ] && [ "${BUILD_ID}" != "${container_host_build_id}" ]; then exit 1; fi
if [ -n "${VARIANT_ID:+set}" ] && [ "${VARIANT_ID}" != "${container_host_variant_id}" ]; then exit 1; fi
cd /tmp; (cd /run/host; md5sum os-release) | md5sum -c
if echo test >>/run/host/os-release; then exit 1; fi
'

    local _os_release_source="/etc/os-release"
    if [[ ! -r "${_os_release_source}" ]]; then
        _os_release_source="/usr/lib/os-release"
    elif [[ -L "${_os_release_source}" ]] && rm /etc/os-release; then
        # Ensure that /etc always wins if available
        cp /usr/lib/os-release /etc
        echo MARKER=1 >>/etc/os-release
    fi

    systemd-nspawn --register=no -D /testsuite-13.nc-container --bind="${_os_release_source}":/tmp/os-release /bin/sh -x -e -c "$_cmd"

    if grep -q MARKER /etc/os-release; then
        rm /etc/os-release
        ln -s ../usr/lib/os-release /etc/os-release
    fi
}

function check_machinectl_bind {
    local _cmd='for i in $(seq 1 20); do if test -f /tmp/marker; then exit 0; fi; usleep 500000; done; exit 1;'

    cat >/run/systemd/system/nspawn_machinectl_bind.service <<EOF
[Service]
Type=notify
ExecStart=systemd-nspawn ${SUSE_OPTS[@]} -D /testsuite-13.nc-container --notify-ready=no /bin/sh -x -e -c "$_cmd"
EOF

    systemctl start nspawn_machinectl_bind.service

    touch /tmp/marker

    machinectl bind --mkdir testsuite-13.nc-container /tmp/marker

    while systemctl show -P SubState nspawn_machinectl_bind.service | grep -q running
    do
        sleep 0.1
    done

    return "$(systemctl show -P ExecMainStatus nspawn_machinectl_bind.service)"
}

function check_selinux {
    if ! command -v selinuxenabled >/dev/null || ! selinuxenabled; then
        echo >&2 "SELinux is not enabled, skipping SELinux-related tests"
        return 0
    fi

    # Basic test coverage to avoid issues like https://github.com/systemd/systemd/issues/19976
    systemd-nspawn "${SUSE_OPTS[@]}" --register=no -b -D /testsuite-13.nc-container --selinux-apifs-context=system_u:object_r:container_file_t:s0:c0,c1 --selinux-context=system_u:system_r:container_t:s0:c0,c1
}

function check_ephemeral_config {
    # https://github.com/systemd/systemd/issues/13297

    mkdir -p /run/systemd/nspawn/
    cat >/run/systemd/nspawn/testsuite-13.nc-container.nspawn <<EOF
[Files]
BindReadOnly=/tmp/ephemeral-config
EOF
    touch /tmp/ephemeral-config

    # /testsuite-13.nc-container is prepared by test.sh
    systemd-nspawn --register=no -D /testsuite-13.nc-container --ephemeral /bin/sh -x -c "test -f /tmp/ephemeral-config"

    systemd-nspawn --register=no -D /testsuite-13.nc-container --ephemeral --machine foobar /bin/sh -x -c "! test -f /tmp/ephemeral-config"

    rm -f /run/systemd/nspawn/testsuite-13.nc-container.nspawn
}

function run {
    if [[ "$1" = "yes" && "$is_v2_supported" = "no" ]]; then
        printf "Unified cgroup hierarchy is not supported. Skipping.\n" >&2
        return 0
    fi
    if [[ "$2" = "yes" && "$is_cgns_supported" = "no" ]];  then
        printf "CGroup namespaces are not supported. Skipping.\n" >&2
        return 0
    fi

    local _root="/var/lib/machines/testsuite-13.unified-$1-cgns-$2-api-vfs-writable-$3"
    rm -rf "$_root"
    /usr/lib/systemd/tests/testdata/create-busybox-container "$_root"
    SYSTEMD_NSPAWN_UNIFIED_HIERARCHY="$1" SYSTEMD_NSPAWN_USE_CGNS="$2" SYSTEMD_NSPAWN_API_VFS_WRITABLE="$3" systemd-nspawn --register=no -D "$_root" -b
    SYSTEMD_NSPAWN_UNIFIED_HIERARCHY="$1" SYSTEMD_NSPAWN_USE_CGNS="$2" SYSTEMD_NSPAWN_API_VFS_WRITABLE="$3" systemd-nspawn --register=no -D "$_root" --private-network -b

    if SYSTEMD_NSPAWN_UNIFIED_HIERARCHY="$1" SYSTEMD_NSPAWN_USE_CGNS="$2" SYSTEMD_NSPAWN_API_VFS_WRITABLE="$3" systemd-nspawn --register=no -D "$_root" -U -b; then
        [[ "$is_user_ns_supported" = "yes" && "$3" = "network" ]] && return 1
    else
        [[ "$is_user_ns_supported" = "no" && "$3" = "network" ]] && return 1
    fi

    if SYSTEMD_NSPAWN_UNIFIED_HIERARCHY="$1" SYSTEMD_NSPAWN_USE_CGNS="$2" SYSTEMD_NSPAWN_API_VFS_WRITABLE="$3" systemd-nspawn --register=no -D "$_root" --private-network -U -b; then
        [[ "$is_user_ns_supported" = "yes" && "$3" = "yes" ]] && return 1
    else
        [[ "$is_user_ns_supported" = "no" && "$3" = "yes" ]] && return 1
    fi

    local _netns_opt="--network-namespace-path=/proc/self/ns/net"
    local _net_opts=(
        "--network-bridge=lo"
        "--network-interface=lo"
        "--network-ipvlan=lo"
        "--network-macvlan=lo"
        "--network-veth"
        "--network-veth-extra=lo"
        "--network-zone=zone"
    )

    # --network-namespace-path and network-related options cannot be used together
    for netopt in "${_net_opts[@]}"; do
        echo "$_netns_opt in combination with $netopt should fail"
        if SYSTEMD_NSPAWN_UNIFIED_HIERARCHY="$1" SYSTEMD_NSPAWN_USE_CGNS="$2" SYSTEMD_NSPAWN_API_VFS_WRITABLE="$3" systemd-nspawn --register=no -D "$_root" -b "$_netns_opt" "$netopt"; then
            echo >&2 "unexpected pass"
            return 1
        fi
    done

    # allow combination of --network-namespace-path and --private-network
    if ! SYSTEMD_NSPAWN_UNIFIED_HIERARCHY="$1" SYSTEMD_NSPAWN_USE_CGNS="$2" SYSTEMD_NSPAWN_API_VFS_WRITABLE="$3" systemd-nspawn --register=no -D "$_root" -b "$_netns_opt" --private-network; then
        return 1
    fi

    # test --network-namespace-path works with a network namespace created by "ip netns"
    ip netns add nspawn_test
    _netns_opt="--network-namespace-path=/run/netns/nspawn_test"
    SYSTEMD_NSPAWN_UNIFIED_HIERARCHY="$1" SYSTEMD_NSPAWN_USE_CGNS="$2" SYSTEMD_NSPAWN_API_VFS_WRITABLE="$3" systemd-nspawn --register=no -D "$_root" "$_netns_opt" /bin/ip a | grep -v -E '^1: lo.*UP'
    local r=$?
    ip netns del nspawn_test

    if [[ $r -ne 0 ]]; then
        return 1
    fi

    return 0
}

check_bind_tmp_path

check_norbind

check_rootidmap

check_notification_socket

check_os_release

for api_vfs_writable in yes no network; do
    run no no $api_vfs_writable
    run yes no $api_vfs_writable
    run no yes $api_vfs_writable
    run yes yes $api_vfs_writable
done

check_machinectl_bind

check_selinux

check_ephemeral_config

touch /testok
