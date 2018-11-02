#!/bin/bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -e
TEST_DESCRIPTION="systemd-nspawn smoke test"
TEST_NO_NSPAWN=1

. $TEST_BASE_DIR/test-functions

test_setup() {
    create_empty_image
    mkdir -p $TESTDIR/root
    mount ${LOOPDEV}p1 $TESTDIR/root

    # Create what will eventually be our root filesystem onto an overlay
    (
        LOG_LEVEL=5
        eval $(udevadm info --export --query=env --name=${LOOPDEV}p2)

        setup_basic_environment
        dracut_install busybox chmod rmdir unshare ip

        # mask some services that we do not want to run in these tests
        ln -fs /dev/null $initdir/etc/systemd/system/systemd-hwdb-update.service
        ln -fs /dev/null $initdir/etc/systemd/system/systemd-journal-catalog-update.service
        ln -fs /dev/null $initdir/etc/systemd/system/systemd-networkd.service
        ln -fs /dev/null $initdir/etc/systemd/system/systemd-networkd.socket
        ln -fs /dev/null $initdir/etc/systemd/system/systemd-resolved.service
        ln -fs /dev/null $initdir/etc/systemd/system/systemd-machined.service

        cp create-busybox-container $initdir/

        ./create-busybox-container $initdir/nc-container
        initdir="$initdir/nc-container" dracut_install nc ip

        # setup the testsuite service
        cat >$initdir/etc/systemd/system/testsuite.service <<EOF
[Unit]
Description=Testsuite service

[Service]
ExecStart=/test-nspawn.sh
Type=oneshot
StandardOutput=tty
StandardError=tty
EOF

        cat >$initdir/test-nspawn.sh <<'EOF'
#!/bin/bash
set -x
set -e
set -u
set -o pipefail

export SYSTEMD_LOG_LEVEL=debug

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
if unshare -U sh -c :; then
    is_user_ns_supported=yes
fi

function check_bind_tmp_path {
    # https://github.com/systemd/systemd/issues/4789
    local _root="/var/lib/machines/bind-tmp-path"
    /create-busybox-container "$_root"
    >/tmp/bind
    systemd-nspawn --register=no -D "$_root" --bind=/tmp/bind /bin/sh -c 'test -e /tmp/bind'
}

function check_notification_socket {
    # https://github.com/systemd/systemd/issues/4944
    local _cmd='echo a | $(busybox which nc) -U -u -w 1 /run/systemd/nspawn/notify'
    systemd-nspawn --register=no -D /nc-container /bin/sh -x -c "$_cmd"
    systemd-nspawn --register=no -D /nc-container -U /bin/sh -x -c "$_cmd"
}

function run {
    if [[ "$1" = "yes" && "$is_v2_supported" = "no" ]]; then
        printf "Unified cgroup hierarchy is not supported. Skipping.\n" >&2
        return 0
    fi
    if [[ "$2" = "yes" && "$is_cgns_supported" = "no" ]];  then
        printf "Cgroup namespaces are not supported. Skipping.\n" >&2
        return 0
    fi

    local _root="/var/lib/machines/unified-$1-cgns-$2-api-vfs-writable-$3"
    /create-busybox-container "$_root"
    UNIFIED_CGROUP_HIERARCHY="$1" SYSTEMD_NSPAWN_USE_CGNS="$2" SYSTEMD_NSPAWN_API_VFS_WRITABLE="$3" systemd-nspawn --register=no -D "$_root" -b
    UNIFIED_CGROUP_HIERARCHY="$1" SYSTEMD_NSPAWN_USE_CGNS="$2" SYSTEMD_NSPAWN_API_VFS_WRITABLE="$3" systemd-nspawn --register=no -D "$_root" --private-network -b

    if UNIFIED_CGROUP_HIERARCHY="$1" SYSTEMD_NSPAWN_USE_CGNS="$2" SYSTEMD_NSPAWN_API_VFS_WRITABLE="$3" systemd-nspawn --register=no -D "$_root" -U -b; then
       [[ "$is_user_ns_supported" = "yes" && "$3" = "network" ]] && return 1
    else
       [[ "$is_user_ns_supported" = "no" && "$3" = "network" ]] && return 1
    fi

    if UNIFIED_CGROUP_HIERARCHY="$1" SYSTEMD_NSPAWN_USE_CGNS="$2" SYSTEMD_NSPAWN_API_VFS_WRITABLE="$3" systemd-nspawn --register=no -D "$_root" --private-network -U -b; then
       [[ "$is_user_ns_supported" = "yes" && "$3" = "yes" ]] && return 1
    else
       [[ "$is_user_ns_supported" = "no" && "$3" = "yes" ]] && return 1
    fi

    local _netns_opt="--network-namespace-path=/proc/self/ns/net"

    # --network-namespace-path and network-related options cannot be used together
    if UNIFIED_CGROUP_HIERARCHY="$1" SYSTEMD_NSPAWN_USE_CGNS="$2" SYSTEMD_NSPAWN_API_VFS_WRITABLE="$3" systemd-nspawn --register=no -D "$_root" "$_netns_opt" --network-interface=lo -b; then
       return 1
    fi

    if UNIFIED_CGROUP_HIERARCHY="$1" SYSTEMD_NSPAWN_USE_CGNS="$2" SYSTEMD_NSPAWN_API_VFS_WRITABLE="$3" systemd-nspawn --register=no -D "$_root" "$_netns_opt" --network-macvlan=lo -b; then
       return 1
    fi

    if UNIFIED_CGROUP_HIERARCHY="$1" SYSTEMD_NSPAWN_USE_CGNS="$2" SYSTEMD_NSPAWN_API_VFS_WRITABLE="$3" systemd-nspawn --register=no -D "$_root" "$_netns_opt" --network-ipvlan=lo -b; then
       return 1
    fi

    if UNIFIED_CGROUP_HIERARCHY="$1" SYSTEMD_NSPAWN_USE_CGNS="$2" SYSTEMD_NSPAWN_API_VFS_WRITABLE="$3" systemd-nspawn --register=no -D "$_root" "$_netns_opt" --network-veth -b; then
       return 1
    fi

    if UNIFIED_CGROUP_HIERARCHY="$1" SYSTEMD_NSPAWN_USE_CGNS="$2" SYSTEMD_NSPAWN_API_VFS_WRITABLE="$3" systemd-nspawn --register=no -D "$_root" "$_netns_opt" --network-veth-extra=lo -b; then
       return 1
    fi

    if UNIFIED_CGROUP_HIERARCHY="$1" SYSTEMD_NSPAWN_USE_CGNS="$2" SYSTEMD_NSPAWN_API_VFS_WRITABLE="$3" systemd-nspawn --register=no -D "$_root" "$_netns_opt" --network-bridge=lo -b; then
       return 1
    fi

    if UNIFIED_CGROUP_HIERARCHY="$1" SYSTEMD_NSPAWN_USE_CGNS="$2" SYSTEMD_NSPAWN_API_VFS_WRITABLE="$3" systemd-nspawn --register=no -D "$_root" "$_netns_opt" --network-zone=zone -b; then
       return 1
    fi

    if UNIFIED_CGROUP_HIERARCHY="$1" SYSTEMD_NSPAWN_USE_CGNS="$2" SYSTEMD_NSPAWN_API_VFS_WRITABLE="$3" systemd-nspawn --register=no -D "$_root" "$_netns_opt" --private-network -b; then
       return 1
    fi

    # test --network-namespace-path works with a network namespace created by "ip netns"
    ip netns add nspawn_test
    _netns_opt="--network-namespace-path=/run/netns/nspawn_test"
    UNIFIED_CGROUP_HIERARCHY="$1" SYSTEMD_NSPAWN_USE_CGNS="$2" SYSTEMD_NSPAWN_API_VFS_WRITABLE="$3" systemd-nspawn --register=no -D "$_root" "$_netns_opt" /bin/ip a | grep -v -E '^1: lo.*UP'
    local r=$?
    ip netns del nspawn_test

    if [ $r -ne 0 ]; then
       return 1
    fi

    return 0
}

check_bind_tmp_path

check_notification_socket

for api_vfs_writable in yes no network; do
    run no no $api_vfs_writable
    run yes no $api_vfs_writable
    run no yes $api_vfs_writable
    run yes yes $api_vfs_writable
done

touch /testok
EOF

        chmod 0755 $initdir/test-nspawn.sh
        setup_testsuite
    ) || return 1

    ddebug "umount $TESTDIR/root"
    umount $TESTDIR/root
}

do_test "$@"
