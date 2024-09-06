#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="Tests for auxiliary utilities"
NSPAWN_ARGUMENTS="--private-network"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

# Make sure vsock is available in the VM
CID=$((RANDOM + 3))
QEMU_OPTIONS+=" -device vhost-vsock-pci,guest-cid=$CID"

test_append_files() {
    local workspace="${1:?}"

    if ! get_bool "${TEST_PREFER_NSPAWN:-}" && ! get_bool "${TEST_NO_QEMU:-}"; then
        # Check if we can correctly boot with an invalid machine ID only if we run
        # the QEMU test, as nspawn refuses the invalid machine ID with -EUCLEAN
        printf "556f48e837bc4424a710fa2e2c9d3e3c\ne3d\n" >"$workspace/etc/machine-id"
    fi

    if host_has_btrfs && host_has_mdadm; then
        install_btrfs
        install_mdadm
        generate_module_dependencies
    fi

    inst_binary socat
    inst_binary ssh
    inst_binary sshd
    inst_binary ssh-keygen
    image_install -o /usr/lib/ssh/sshd-session /usr/libexec/openssh/sshd-session
    inst_binary usermod
    instmods vmw_vsock_virtio_transport
    instmods vsock_loopback
    instmods vmw_vsock_vmci_transport
    generate_module_dependencies
}

do_test "$@"
