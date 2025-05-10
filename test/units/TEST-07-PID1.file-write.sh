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
CONTAINER_ROOT_DIR=$(mktemp -d -t "${TEST_ID}-root-XXXX")

# Mount points:
HOST_MOUNT_DIR=$(mktemp -d -t test-dir-XXXX)
CONTAINER_MOUNT_DIR="/${TEST_ID}"

# Internal service config and output
FILE_WR_SERVICE="${TEST_ID}.service"
OUTPUT_FILE=$(mktemp test-service-output-XXXX)
OUTPUT_CONTENTS='Test service is running'


# This is a dummy procfs mount
HELPER_PROC=$(mktemp -d -t helper-proc-XXXX)

# Make test service that writes to a file
config_container_service() {
    # Create a test-service unit file that will run via the container's systemd
    local container_systemd_dir="${CONTAINER_ROOT_DIR}/etc/systemd/system"
    local service_output="${CONTAINER_MOUNT_DIR}/${OUTPUT_FILE}"
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
    # NOTE: This warns with "test-service.service is added as a dependency to a non-existent unit multi-user.target."
    systemctl --root="$CONTAINER_ROOT_DIR" enable test-service.service
}
make_mounts() {
    # Host bind mount for the output file. Systemd will make the container's version.
    mkdir -p "$HOST_MOUNT_DIR"

    # Dummy procfs mount
    # TODO: explain why this is needed
    mount -t proc proc "$HELPER_PROC"

    # Container root tmpfs mount
    mount --mkdir -t tmpfs tmpfs "$CONTAINER_ROOT_DIR"
    # Container's /usr will be a read-only bind mount of the host's /usr
    mount --mkdir --bind /usr "${CONTAINER_ROOT_DIR}/usr"
    mount -o remount,bind,ro "${CONTAINER_ROOT_DIR}/usr"
}
testcase_multiple_features() {

    make_mounts

    config_container_service

    local bind_mount_arg="${HOST_MOUNT_DIR}:${CONTAINER_MOUNT_DIR}"
    local host_output="${HOST_MOUNT_DIR}/${OUTPUT_FILE}"
    # Run the container as a transient unit and wait for it to finish
    systemd-run \
    --unit "$FILE_WR_SERVICE" \
    --wait \
    -p BindReadOnlyPaths=/etc/machine-id \
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

    # If our service ran, we should be able to read its output here
    assert_eq "$(cat "${host_output}")" "$OUTPUT_CONTENTS"
}

at_exit() {
    set +e

    umount "$HELPER_PROC"
    rmdir  "$HELPER_PROC"

    umount -l "$CONTAINER_ROOT_DIR/usr"
    umount -l "$CONTAINER_ROOT_DIR"

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
