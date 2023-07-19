#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="Basic systemd setup"
IMAGE_NAME="basic"
RUN_IN_UNPRIVILEGED_CONTAINER=${RUN_IN_UNPRIVILEGED_CONTAINER:-yes}
TEST_REQUIRE_INSTALL_TESTS=0
TEST_SUPPORTING_SERVICES_SHOULD_BE_MASKED=0

# Check if we can correctly deserialize if the kernel cmdline contains "weird" stuff
# like an invalid argument, "end of arguments" separator, or a sysvinit argument (-z)
# See: https://github.com/systemd/systemd/issues/28184
KERNEL_APPEND="foo -- -z bar --- baz $KERNEL_APPEND"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_append_files() {
    # install tests manually so the test is functional even when -Dinstall-tests=false
    local dst="${1:?}/usr/lib/systemd/tests/testdata/units/"
    mkdir -p "$dst"
    cp -v "$TEST_UNITS_DIR"/{testsuite-01,end}.service "$TEST_UNITS_DIR/testsuite.target" "$dst"
}

# Setup a one shot service in initrd that creates a dummy bind mount under /run
# to check if the mount persists though the initrd transition. The "check" part
# is in the respective testsuite-01.sh script.
#
# See: https://github.com/systemd/systemd/issues/28452
run_qemu_hook() {
    local extra="$WORKDIR/initrd.extra"

    mkdir -m 755 "$extra"
    mkdir -m 755 "$extra/etc" "$extra/etc/systemd" "$extra/etc/systemd/system" "$extra/etc/systemd/system/initrd.target.wants"

    cat >"$extra/etc/systemd/system/initrd-run-mount.service" <<EOF
[Unit]
Description=Create a mount in /run that should survive the transition from initrd

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=sh -xec "mkdir /run/initrd-mount-source /run/initrd-mount-target; mount -v --bind /run/initrd-mount-source /run/initrd-mount-target"
EOF
    ln -svrf "$extra/etc/systemd/system/initrd-run-mount.service" "$extra/etc/systemd/system/initrd.target.wants/initrd-run-mount.service"

    (cd "$extra" && find . | cpio -o -H newc -R root:root > "$extra.cpio")

    INITRD_EXTRA="$extra.cpio"
}

do_test "$@"
