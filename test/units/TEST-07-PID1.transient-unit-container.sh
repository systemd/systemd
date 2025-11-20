#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -Eeuo pipefail
set -x

# -----------------------------------------------------------------------------
#
# Test: PID-1 Transient Unit Container
#
# Verifies that a minimal systemd PID 1 inside a tmpfs root can:
#   • Boot
#   • Bind mount the host's /usr directory read-only
#   • Bind mount a shared writable directory with the host
#   • Run a one-shot service in the container to create and
#     write to a host file in that directory
#   • Exit cleanly with systemd-run --wait propagating status
#
# -----------------------------------------------------------------------------

# Helpers
# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh
# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Mounts and directories to teardown and cleanup
CLEANUP_MOUNTS=()
CLEANUP_PATHS=()

# Common Config:
TEST_NAME="TEST-07-PID1.transient-unit-container"
OUTPUT_FILE="test-service-output"
EXPECTED_OUTPUT="Test service is running"
readonly TEST_NAME OUTPUT_FILE EXPECTED_OUTPUT

# Host FS Directories
# mktemp helps avoid name collision; using dry-run mode
CONTAINER_ROOT_FS=$(mktemp -u -d --tmpdir "${TEST_NAME}-root-XXXX")
HOST_OUT_DIR=$(mktemp -u -d --tmpdir test-dir-XXXX)
readonly CONTAINER_ROOT_FS HOST_OUT_DIR

# Container FS Directories
CONTAINER_MOUNT_DIR="/${TEST_NAME}"
readonly CONTAINER_MOUNT_DIR

# Mount a dummy /proc FS which will not be passed to the container. It
# circumvents a permissions error when attempting to mount a FS within the
# container. This seems like a systemd bug.
temporary_mount_hack() {
    # IMPORTANT: This is modeled after a workaround in
    # TEST-07-PID1.private-pids.sh with a key difference. In private-pids, it's
    # explained there must be at least 1 unmasked procfs mount on the host in
    # order for /proc/ to be mounted by an UNPRIVILEGED user within the container
    # namespace. Note the host mount is not actually passed through to the
    # container.
    #
    # The key difference here is that, here, systemd-run is NOT launched with
    # --user, it is a PRIVILEGED environment and should not hit a permissions
    # error when attempting to mount /proc. Unfortunately, that's exactly what
    # happens if you launch the container without first mounting a dummy
    # unmasked /proc on the host.
    #
    # It was pointed out to me that this may indicate a significant bug. A
    # change masking the host's /proc could prevent the startup of privileged
    # containers. If this were addressed, this function could be removed.

    local -r helper_proc=$(mktemp -d --tmpdir helper-proc-XXXX)
    CLEANUP_PATHS+=("$helper_proc")

    mount -t proc proc "$helper_proc"
    CLEANUP_MOUNTS+=("$helper_proc")
}

# Mount 1) a writable directory for output; 2) a dummy procfs as a workaround so
# the container can mount /proc; 3) a tmpfs to serve as the container's root
# FS; 4) the host's /usr directory read only.
make_mounts() {
    # Host bind mount for the output file. Systemd will make the container's version.
    mkdir -p "$HOST_OUT_DIR"
    CLEANUP_PATHS+=("$HOST_OUT_DIR")

    temporary_mount_hack

    # Container root tmpfs mount
    mkdir -p "$CONTAINER_ROOT_FS"
    CLEANUP_PATHS+=("$CONTAINER_ROOT_FS")

    mount -t tmpfs tmpfs "$CONTAINER_ROOT_FS"
    CLEANUP_MOUNTS+=("$CONTAINER_ROOT_FS")

    # Container's /usr will be a read-only bind mount of the host's /usr. Tried
    # using -p BindReadOnlyPaths=/usr instead of this, but that didn't work.
    # Debugging that got hairy, so I'm going with this for now.
    mkdir -p "${CONTAINER_ROOT_FS}/usr"

    mount --bind /usr "${CONTAINER_ROOT_FS}/usr"
    mount -o remount,bind,ro "${CONTAINER_ROOT_FS}/usr"

    # Make sure /root/usr is unmounted before /root.
    # Don't add to CLEANUP_PATHS because it will be removed when /root is.
    CLEANUP_MOUNTS=( "${CONTAINER_ROOT_FS}/usr" "${CLEANUP_MOUNTS[@]}" )
}

# Create a test-service unit file that will run via the container's systemd and
# write the output file.
config_container_service() {
    local -r container_systemd_dir="${CONTAINER_ROOT_FS}/etc/systemd/system"
    local -r guest_output="${CONTAINER_MOUNT_DIR}/${OUTPUT_FILE}"
    local -r internal_test_service="${container_systemd_dir}/test-service.service"

    mkdir -p "$container_systemd_dir"

    # Generate a phony random machine-id for the container
    uuidgen -r | tr -d '-' | tr '[:upper:]' '[:lower:]' > "${CONTAINER_ROOT_FS}/etc/machine-id"

    cat <<EOF >"$internal_test_service"
[Unit]
Description=Test Service for Internal Systemd
After=basic.target

[Service]
Type=oneshot
ExecStart=sh -c 'echo "$EXPECTED_OUTPUT"  > "$guest_output"'
ExecStartPost=systemctl --no-block exit 0
TimeoutStopSec=15s

[Install]
WantedBy=multi-user.target
EOF
    systemctl --root="$CONTAINER_ROOT_FS" enable test-service.service
}

# The testcase. Configs cleanup trap, makes mounts, configs internal service
# unit, kicks off container as a transient unit, waits for it to finish and
# checks output.
testcase_transient_unit_container_file_write() {

    # Cleanup on exit. Test cases seem to run in a subshell, and only a single
    # testcase is expected in this file. So we tie cleanup to the lifetime of
    # this subshell, not the global context, allowing for appending to
    # CLEANUP_PATHS and CLEANUP_MOUNTS
    trap file_write_cleanup EXIT ERR INT TERM

    make_mounts

    config_container_service

    # Run the container as a transient unit and wait for it to finish
    local -r bind_mount_arg="${HOST_OUT_DIR}:${CONTAINER_MOUNT_DIR}"
    local -r service_unit_name="${TEST_NAME}.service"

    SYSTEMD_LOG_LEVEL=debug SYSTEMD_LOG_TARGET=console \
    systemd-run \
    --unit "$service_unit_name" \
    --wait \
    -p RootDirectory="$CONTAINER_ROOT_FS" \
    -p PrivatePIDs=yes \
    -p PrivateUsersEx=full \
    -p ProtectHostname=private \
    -p ProtectControlGroupsEx=private \
    -p PrivateMounts=yes \
    -p PrivateNetwork=yes \
    -p PrivateDevices=yes \
    -p PrivateIPC=yes \
    -p BindLogSockets=no \
    -p "Environment=container=transient-unit" \
    -p "CapabilityBoundingSet=~CAP_SYS_TIME CAP_SYS_BOOT CAP_AUDIT_READ" \
    -p Type=exec \
    -p Delegate=true \
    -p DelegateSubgroup=init.scope \
    -p DelegateNamespaces=yes \
    -p BindPaths="$bind_mount_arg" \
    /usr/lib/systemd/systemd multi-user.target

    # If our service ran, we should be able to read its output here
    local -r host_output="${HOST_OUT_DIR}/${OUTPUT_FILE}"
    assert_eq "$(cat "${host_output}")" "$EXPECTED_OUTPUT"
}

CLEANUP_DONE=0
file_write_cleanup() {
    # Avoid re-running this function. E.g. At both SIGINT and EXIT.
    (( CLEANUP_DONE )) && return
    CLEANUP_DONE=1
    set +e

    # Remove all the mounts and directories we created
    # These variables reset to empty arrays when the subprocess concludes.
    umount "${CLEANUP_MOUNTS[@]}"
    rm -rf "${CLEANUP_PATHS[@]}"
}

run_testcases
