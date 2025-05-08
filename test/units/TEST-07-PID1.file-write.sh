#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh
# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

TEST_ID=TEST-07-PID1-file-write
CONTAINER_ROOT_DIR="/tmp/${TEST_ID}-root"

HOST_MOUNT_DIR=/tmp/test-dir
INTERNAL_MOUNT_DIR="/${TEST_ID}"

FILE_WR_SERVICE="${TEST_ID}.service"
OUTPUT_FILE=test-service-output

OUTPUT_CONTENTS='Test service is running'

# Make test service that writes to a file
internal_writer() {
    # Create a test service that will run in the internal systemd
    local container_systemd_dir="${CONTAINER_ROOT_DIR}/usr/lib/systemd/system"
    local service_output="${INTERNAL_MOUNT_DIR}/${OUTPUT_FILE}"
    local internal_test_service="${container_systemd_dir}/test-service.service"

    mkdir -p "$container_systemd_dir"
    cat <<EOF >"$internal_test_service"
[Unit]
Description=Test Service for Internal Systemd
After=basic.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'echo "$OUTPUT_CONTENTS"  > "$service_output"'
ExecStartPost=/usr/bin/systemctl --no-block exit 0
TimeoutStopSec=15s

[Install]
WantedBy=multi-user.target
EOF

    systemctl --root="$CONTAINER_ROOT_DIR" enable test-service.service
}

testcase_multiple_features() {
    local squashed_container_image=/usr/share/minimal_2.raw
    local bind_mount_arg="${HOST_MOUNT_DIR}:${INTERNAL_MOUNT_DIR}"
    local host_output="${HOST_MOUNT_DIR}/${OUTPUT_FILE}"

    unsquashfs -no-xattrs -d "$CONTAINER_ROOT_DIR" "$squashed_container_image"

    internal_writer

    # We'll bind mount this directory to the container
    # The internal directory will be created by systemd-run
    mkdir -p "$HOST_MOUNT_DIR"

    # intentionally declared globally so it's valid if cleanup runs at exit
    helper_proc=$(mktemp -d /tmp/helper-proc-XXXX)
    mount -t proc proc "$helper_proc"

    cleanup() {
        # OR prevents exit if the command fails during cleanup
        umount -l "$helper_proc" || true
        rmdir  "$helper_proc"
    }

    trap cleanup EXIT

    systemd-run \
    --unit "$FILE_WR_SERVICE" \
    --wait \
    -p RootDirectory="$CONTAINER_ROOT_DIR" \
    -p PrivatePIDs=yes \
    -p PrivateUsersEx=full \
    -p ProtectHostnameEx=private \
    -p ProtectControlGroupsEx=private \
    -p PrivateMounts=yes \
    -p PrivateNetwork=yes \
    -p PrivateDevices=yes \
    -p PrivateIPC=yes \
    -p BindLogSockets=no \
    -p "Environment=container=lxc" \
    -p "CapabilityBoundingSet=~CAP_SYS_TIME CAP_SYS_BOOT CAP_AUDIT_READ" \
    -p Type=exec \
    -p Delegate=true \
    -p DelegateSubgroup=task \
    -p DelegateNamespaces=yes \
    -p BindPaths="$bind_mount_arg" \
    /usr/lib/systemd/systemd multi-user.target

    # If our service ran, we should be able to read it's output here
    assert_eq "$(cat ${host_output})" "$OUTPUT_CONTENTS"
}

at_exit() {
    set +e
    # Remove any test files
    rm -rf "$CONTAINER_ROOT_DIR" "$HOST_MOUNT_DIR"

    # If the service is still running, kill it
    if systemctl is-active --quiet "$FILE_WR_SERVICE"; then
        systemctl kill --signal=KILL "$FILE_WR_SERVICE"
    fi
    # Remove any failed transient units
    systemctl reset-failed
}

trap at_exit EXIT ERR INT

run_testcases
