#!/bin/bash
set -e
TEST_DESCRIPTION="/etc/machine-id testing"
TEST_NO_NSPAWN=1

. $TEST_BASE_DIR/test-functions

test_setup() {
    create_empty_image_rootdir

    # Create what will eventually be our root filesystem onto an overlay
    (
        LOG_LEVEL=5
        eval $(udevadm info --export --query=env --name=${LOOPDEV}p2)

        setup_basic_environment
        printf "556f48e837bc4424a710fa2e2c9d3e3c\ne3d\n" >$initdir/etc/machine-id
        dracut_install mount cmp

        # setup the testsuite service
        cat >$initdir/etc/systemd/system/testsuite.service <<EOF
[Unit]
Description=Testsuite service

[Service]
ExecStart=/bin/sh -e -x -c '/test-machine-id-setup.sh; systemctl --state=failed --no-legend --no-pager > /failed ; echo OK > /testok'
Type=oneshot
EOF

cat >$initdir/test-machine-id-setup.sh <<'EOF'
#!/bin/bash

set -e
set -x

function setup_root {
    local _root="$1"
    mkdir -p "$_root"
    mount -t tmpfs tmpfs "$_root"
    mkdir -p "$_root/etc" "$_root/run"
}

function check {
    printf "Expected\n"
    cat "$1"
    printf "\nGot\n"
    cat "$2"
    cmp "$1" "$2"
}

r="$(pwd)/overwrite-broken-machine-id"
setup_root "$r"
systemd-machine-id-setup --print --root "$r"
echo abc >>"$r/etc/machine-id"
id=$(systemd-machine-id-setup --print --root "$r")
echo $id >expected
check expected "$r/etc/machine-id"

r="$(pwd)/transient-machine-id"
setup_root "$r"
systemd-machine-id-setup --print --root "$r"
echo abc >>"$r/etc/machine-id"
mount -o remount,ro "$r"
mount -t tmpfs tmpfs "$r/run"
transient_id=$(systemd-machine-id-setup --print --root "$r")
mount -o remount,rw "$r"
commited_id=$(systemd-machine-id-setup --print --commit --root "$r")
[[ "$transient_id" = "$commited_id" ]]
check "$r/etc/machine-id" "$r/run/machine-id"
EOF
chmod +x $initdir/test-machine-id-setup.sh

        setup_testsuite
    )

    # mask some services that we do not want to run in these tests
    ln -fs /dev/null $initdir/etc/systemd/system/systemd-hwdb-update.service
    ln -fs /dev/null $initdir/etc/systemd/system/systemd-journal-catalog-update.service
    ln -fs /dev/null $initdir/etc/systemd/system/systemd-networkd.service
    ln -fs /dev/null $initdir/etc/systemd/system/systemd-networkd.socket
    ln -fs /dev/null $initdir/etc/systemd/system/systemd-resolved.service
}

do_test "$@"
