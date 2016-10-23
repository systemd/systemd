#!/bin/bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
TEST_DESCRIPTION="systemd-nspawn smoke test"
SKIP_INITRD=yes
. $TEST_BASE_DIR/test-functions

check_result_qemu() {
    ret=1
    mkdir -p $TESTDIR/root
    mount ${LOOPDEV}p1 $TESTDIR/root
    [[ -e $TESTDIR/root/testok ]] && ret=0
    [[ -f $TESTDIR/root/failed ]] && cp -a $TESTDIR/root/failed $TESTDIR
    cp -a $TESTDIR/root/var/log/journal $TESTDIR
    umount $TESTDIR/root
    [[ -f $TESTDIR/failed ]] && cat $TESTDIR/failed
    ls -l $TESTDIR/journal/*/*.journal
    test -s $TESTDIR/failed && ret=$(($ret+1))
    return $ret
}

test_run() {
    if run_qemu; then
        check_result_qemu || return 1
    else
        dwarn "can't run QEMU, skipping"
    fi
    return 0
}

test_setup() {
    create_empty_image
    mkdir -p $TESTDIR/root
    mount ${LOOPDEV}p1 $TESTDIR/root

    # Create what will eventually be our root filesystem onto an overlay
    (
        LOG_LEVEL=5
        eval $(udevadm info --export --query=env --name=${LOOPDEV}p2)

        setup_basic_environment
        dracut_install busybox chmod rmdir

        cp create-busybox-container $initdir/

        # setup the testsuite service
        cat >$initdir/etc/systemd/system/testsuite.service <<EOF
[Unit]
Description=Testsuite service
After=multi-user.target

[Service]
ExecStart=/test-nspawn.sh
Type=oneshot
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

function run {
    if [[ "$1" = "yes" && "$is_v2_supported" = "no" ]]; then
        printf "Unified cgroup hierarchy is not supported. Skipping.\n" >&2
        return 0
    fi
    if [[ "$2" = "yes" && "$is_cgns_supported" = "no" ]];  then
        printf "Cgroup namespaces are not supported. Skipping.\n" >&2
        return 0
    fi

    local _root="/var/lib/machines/unified-$1-cgns-$2"
    /create-busybox-container "$_root"
    UNIFIED_CGROUP_HIERARCHY="$1" SYSTEMD_NSPAWN_USE_CGNS="$2" systemd-nspawn --register=no -D "$_root" -b
    UNIFIED_CGROUP_HIERARCHY="$1" SYSTEMD_NSPAWN_USE_CGNS="$2" systemd-nspawn --register=no -D "$_root" --private-network -b
    UNIFIED_CGROUP_HIERARCHY="$1" SYSTEMD_NSPAWN_USE_CGNS="$2" systemd-nspawn --register=no -D "$_root" -U -b
    UNIFIED_CGROUP_HIERARCHY="$1" SYSTEMD_NSPAWN_USE_CGNS="$2" systemd-nspawn --register=no -D "$_root" --private-network -U -b

    return 0
}

run no no
run yes no
run no yes
run yes yes

touch /testok
EOF

        chmod 0755 $initdir/test-nspawn.sh
        setup_testsuite
    ) || return 1

    ddebug "umount $TESTDIR/root"
    umount $TESTDIR/root
}

test_cleanup() {
    umount $TESTDIR/root 2>/dev/null
    [[ $LOOPDEV ]] && losetup -d $LOOPDEV
    return 0
}

do_test "$@"
