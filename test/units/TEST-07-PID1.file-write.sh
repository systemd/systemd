#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -Eeuo pipefail
set -x

# Must be root.  Die early instead of letting mount/systemd‑run blow up later.
if (( EUID )); then
    printf 'This test must be run as root.\n' >&2
    exit 1
fi

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh
# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Cleanup on exit
trap at_exit EXIT ERR INT TERM

readonly TEST_ID=TEST-07-PID1-file-write
CONTAINER_ROOT_DIR=$(mktemp -d --tmpdir "${TEST_ID}-root-XXXX")

# Mount points for host and container
HOST_MOUNT_DIR=$(mktemp -d --tmpdir test-dir-XXXX)
readonly HOST_MOUNT_DIR
readonly CONTAINER_MOUNT_DIR="/${TEST_ID}"

# Internal service config and output
readonly OUTPUT_FILE=test-service-output
readonly OUTPUT_CONTENTS='Test service is running'

# This is a dummy procfs mount
HELPER_PROC=$(mktemp -d --tmpdir helper-proc-XXXX)
readonly HELPER_PROC
make_mounts() {
    # Host bind mount for the output file. Systemd will make the container's version.
    mkdir -p "$HOST_MOUNT_DIR"

    # Dummy procfs mount
    # TODO: explain why this is needed
    mount -t proc proc "$HELPER_PROC"

    # Container root tmpfs mount
    mount --mkdir -t tmpfs tmpfs "$CONTAINER_ROOT_DIR"

    # Container's /usr will be a read-only bind mount of the host's /usr
    # Tried using -p BindReadOnlyPaths=/usr instead of this, but that didn't work.
    # Debugging that got hairy, so I'm going with this for now.
    mount --mkdir --bind /usr "${CONTAINER_ROOT_DIR}/usr"
    mount -o remount,bind,ro "${CONTAINER_ROOT_DIR}/usr"
}

# Create a test-service unit file that will run via the container's systemd and write the output file.
config_container_service() {
    local -r container_systemd_dir="${CONTAINER_ROOT_DIR}/etc/systemd/system"
    local -r service_output="${CONTAINER_MOUNT_DIR}/${OUTPUT_FILE}"
    local -r internal_test_service="${container_systemd_dir}/test-service.service"

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

# Start the container as a transient unit and wait for it to finish. Check that the output file is written
testcase_container_file_write() {

    make_mounts

    config_container_service

    # Run the container as a transient unit and wait for it to finish
    local -r bind_mount_arg="${HOST_MOUNT_DIR}:${CONTAINER_MOUNT_DIR}"
    local -r file_wr_service="${TEST_ID}.service"
    systemd-run \
    --unit "$file_wr_service" \
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

    local -r host_output="${HOST_MOUNT_DIR}/${OUTPUT_FILE}"
    # If our service ran, we should be able to read its output here
    assert_eq "$(cat "${host_output}")" "$OUTPUT_CONTENTS"
}

CLEANUP_DONE=0
at_exit() {
    # Avoid re-running this function. E.g. At both SIGINT and EXIT.
    (( CLEANUP_DONE )) && return
    CLEANUP_DONE=1
    set +e

    # Remove all the mounts and directories we created
    umount "${CONTAINER_ROOT_DIR}/usr" "${CONTAINER_ROOT_DIR}" "${HELPER_PROC}"
    rm -rf "${CONTAINER_ROOT_DIR}" "${HELPER_PROC}" "${HOST_MOUNT_DIR}"

}

run_testcases
