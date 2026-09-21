#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# TDX, direct kernel boot: launch a confidential guest with --linux=/--initrd=.

set -eux
set -o pipefail

# shellcheck source=test/units/TEST-94-COCO/lib.sh
. "$(dirname "$0")"/TEST-94-COCO/lib.sh

if [[ "${COCO_TYPE:?}" != "tdx" ]]; then
    echo "host coco type is '$COCO_TYPE', not tdx, skipping"
    exit 77
fi

MACHINE="coco-tdx-direct-$$"
WORKDIR="$(mktemp -d)"
at_exit() {
    set +e
    machinectl terminate "$MACHINE" 2>/dev/null || :
    rm -rf "$WORKDIR"
}
trap at_exit EXIT INT TERM

vmspawn_boot_coco "$MACHINE" "$COCO_TYPE" "$WORKDIR" 'detect_virt' \
    --image="$IMAGE_DIR/image.raw" \
    --linux="$IMAGE_DIR/image.vmlinuz" \
    --initrd="$IMAGE_DIR/image.initrd" \
    selinux=0 systemd.firstboot=no rw
echo "TDX direct-boot guest correctly reported confidential virtualization"
