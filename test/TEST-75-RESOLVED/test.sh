#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="Tests for systemd-resolved"
TEST_NO_QEMU=1
NSPAWN_ARGUMENTS="--private-network"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_require_bin knotd

test_append_files() {
    # Install knot
    image_install kzonecheck keymgr kjournalprint knotc knotd
    image_install "${ROOTLIBDIR:?}/system/knot.service"
    image_install -o /lib/tmpfiles.d/knot.conf
    image_install -o /etc/dbus-1/system.d/cz.nic.knotd.conf
    image_install -o /etc/default/knot

    # Install DNS-related utilities (usually found in the bind-utils package)
    image_install delv dig host nslookup

    if command -v nft >/dev/null; then
        # Install nftables
        image_install nft
    fi
}

do_test "$@"
