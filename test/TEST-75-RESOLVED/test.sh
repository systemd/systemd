#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="Tests for systemd-resolved"
TEST_NO_QEMU=1
NSPAWN_ARGUMENTS="--private-network"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_require_bin knotd

# We need at least Knot 3.0 which support (among others) the ds-push directive
if ! knotc -c "${TEST_BASE_DIR:?}/knot-data/knot.conf" conf-check; then
    echo "This test requires at least Knot 3.0. skipping..."
    exit 0
fi

test_append_files() {
    local workspace="${1:?}"
    # Install knot
    image_install kzonecheck keymgr kjournalprint knotc knotd
    image_install "${ROOTLIBDIR:?}/system/knot.service"
    image_install -o /lib/tmpfiles.d/knot.conf
    image_install -o /etc/dbus-1/system.d/cz.nic.knotd.conf
    image_install -o /etc/default/knot

    # Copy over our configuration
    mkdir -p "${workspace:?}/var/lib/knot/zones/" "${workspace:?}/etc/knot/"
    cp -rfv "${TEST_BASE_DIR:?}"/knot-data/zones/* "$workspace/var/lib/knot/zones/"
    cp -fv "${TEST_BASE_DIR:?}/knot-data/knot.conf" "$workspace/etc/knot/knot.conf"
    chgrp -R knot "$workspace/etc/knot/" "$workspace/var/lib/knot/"
    chmod -R ug+rwX "$workspace/var/lib/knot/"
    chmod -R g+r "$workspace/etc/knot/"

    # Install DNS-related utilities (usually found in the bind-utils package)
    image_install delv dig host nslookup
}

do_test "$@"
