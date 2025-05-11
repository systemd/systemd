#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -Eeuo pipefail
set -x

# -----------------------------------------------------------------------------
# Test: PID-1 File-Write from Transient Unit Container
#
# Verifies that a minimal systemd PID 1 inside a tmpfs root can:
#   • Bind mount a writable directory
#   • Run a one-shot service in the container to create and
#     write to host file in that directory
#   • Exit cleanly with systemd-run --wait propagating status
#
# -----------------------------------------------------------------------------

# Must be root.
if (( EUID )); then
    printf 'This test must be run as root.\n' >&2
    exit 1
fi

# Helpers
# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh
# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Mounts and directories to teardown and cleanup
TO_UMOUNT=()
TO_RM=()

# Common Config:
TEST_ID="TEST-07-PID1-file-write"
OUTPUT_FILE="test-service-output"
OUTPUT_CONTENTS='Test service is running'
readonly TEST_ID OUTPUT_FILE OUTPUT_CONTENTS

# Host FS Directories
# mktemp helps avoid name collision; using dry-run mode
CONTAINER_ROOT_DIR=$(mktemp -u -d --tmpdir "${TEST_ID}-root-XXXX")
HOST_MOUNT_DIR=$(mktemp -u -d --tmpdir test-dir-XXXX)
readonly CONTAINER_ROOT_DIR HOST_MOUNT_DIR

# Container FS Directories
CONTAINER_MOUNT_DIR="/${TEST_ID}"
readonly CONTAINER_MOUNT_DIR

make_mounts() {
    # Host bind mount for the output file. Systemd will make the container's version.
    mkdir -p "$HOST_MOUNT_DIR"
    TO_RM+=("$HOST_MOUNT_DIR")

    # Dummy procfs mount
    # TODO: explain why this is needed

    # This is a dummy procfs mount
    local -r helper_proc=$(mktemp -d --tmpdir helper-proc-XXXX)
    TO_RM+=("$helper_proc")

    mount -t proc proc "$helper_proc"
    TO_UMOUNT+=("$helper_proc")

    # Container root tmpfs mount
    mkdir -p "$CONTAINER_ROOT_DIR"
    TO_RM+=("$CONTAINER_ROOT_DIR")
    mount -t tmpfs tmpfs "$CONTAINER_ROOT_DIR"
    TO_UMOUNT+=("$CONTAINER_ROOT_DIR")

    # Container's /usr will be a read-only bind mount of the host's /usr
    # Tried using -p BindReadOnlyPaths=/usr instead of this, but that didn't work.
    # Debugging that got hairy, so I'm going with this for now.
    mkdir -p "${CONTAINER_ROOT_DIR}/usr"

    mount --bind /usr "${CONTAINER_ROOT_DIR}/usr"
    mount -o remount,bind,ro "${CONTAINER_ROOT_DIR}/usr"
    # Make sure /root/usr is unmounted before /root.
    # Don't add to TO_RM because it will be removed when /root is.
    TO_UMOUNT=( "${CONTAINER_ROOT_DIR}/usr" "${TO_UMOUNT[@]}" )

}

# Create a test-service unit file that will run via the container's systemd and write the output file.
config_container_service() {
    local -r container_systemd_dir="${CONTAINER_ROOT_DIR}/etc/systemd/system"
    local -r service_output="${CONTAINER_MOUNT_DIR}/${OUTPUT_FILE}"
    local -r internal_test_service="${container_systemd_dir}/test-service.service"

    mkdir -p "$container_systemd_dir"
    # Generate a phony machine-id for the container
    uuidgen -r | tr -d '-' | tr '[:upper:]' '[:lower:]' > "${CONTAINER_ROOT_DIR}/etc/machine-id"

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

    # Cleanup on exit. Test cases seem to run in a subshell, and only a single
    # testcase is expected in this file. So we tie cleanup to the lifetime of
    # this subshell, not the global context, allowing for appending to TO_RM and TO_UMOUNT
    trap file_write_cleanup EXIT ERR INT TERM

    make_mounts

    config_container_service

    # Run the container as a transient unit and wait for it to finish
    local -r bind_mount_arg="${HOST_MOUNT_DIR}:${CONTAINER_MOUNT_DIR}"
    local -r file_wr_service="${TEST_ID}.service"

    # SYSTEMD_LOG_LEVEL=debug SYSTEMD_LOG_TARGET=console \
    systemd-run \
    --unit "$file_wr_service" \
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

    local -r host_output="${HOST_MOUNT_DIR}/${OUTPUT_FILE}"
    # If our service ran, we should be able to read its output here
    assert_eq "$(cat "${host_output}")" "$OUTPUT_CONTENTS"
}

CLEANUP_DONE=0
file_write_cleanup() {
    # Avoid re-running this function. E.g. At both SIGINT and EXIT.
    (( CLEANUP_DONE )) && return
    CLEANUP_DONE=1
    set +e

    # Remove all the mounts and directories we created
    umount "${TO_UMOUNT[@]}"
    rm -rf "${TO_RM[@]}"

}

run_testcases
