#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# SEV-SNP, direct kernel boot: launch a confidential guest with --linux=/--initrd=.

set -eux
set -o pipefail

# shellcheck source=test/units/TEST-94-COCO/lib.sh
. "$(dirname "$0")"/TEST-94-COCO/lib.sh

if [[ "${COCO_TYPE:?}" != "sev-snp" ]]; then
    echo "host coco type is '$COCO_TYPE', not sev-snp, skipping"
    exit 77
fi

MACHINE="coco-snp-direct-$$"
WORKDIR="$(mktemp -d)"
at_exit() {
    set +e
    jobs -p | xargs -r kill 2>/dev/null
    machinectl terminate "$MACHINE" 2>/dev/null || :
    rm -rf "$WORKDIR"
}
trap at_exit EXIT

vmspawn_boot_coco "$MACHINE" "$COCO_TYPE" "$WORKDIR" "" \
    --image="$IMAGE_DIR/image.raw" \
    --linux="$IMAGE_DIR/image.vmlinuz" \
    --initrd="$IMAGE_DIR/image.initrd" \
    selinux=0 systemd.firstboot=no rw
echo "SEV-SNP direct-boot guest correctly reported confidential virtualization"
