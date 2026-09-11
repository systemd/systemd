#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# SEV-SNP, direct kernel boot: launch confidential guests with --linux=/--initrd=.

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
mkdir -p "$WORKDIR/honest" "$WORKDIR/hostile"
at_exit() {
    set +e
    jobs -p | xargs -r kill 2>/dev/null
    machinectl terminate "$MACHINE-honest" 2>/dev/null || :
    machinectl terminate "$MACHINE-hostile" 2>/dev/null || :
    rm -rf "$WORKDIR"
}
trap at_exit EXIT INT TERM

# General test case for SNP direct boot, covers:
#
# - detect_virt: systemd-detect-virt --cvm detects SNP as the CVM type
# - creds_vmspawn: credential transport by vmspawn is working (via initrd for SNP)
# - creds_cmdline: credential transport via cmdline is working (cmdline is measured on SNP)
vmspawn_boot_coco "$MACHINE-honest" "$COCO_TYPE" "$WORKDIR/honest" 'detect_virt creds_vmspawn creds_cmdline' \
    --image="$IMAGE_DIR/image.raw" \
    --linux="$IMAGE_DIR/image.vmlinuz" \
    --initrd="$IMAGE_DIR/image.initrd" \
    --set-credential="$COCO_CRED_TRUSTED_ID:$COCO_CRED_TRUSTED_VALUE" \
    selinux=0 systemd.firstboot=no rw \
    "systemd.set_credential=$COCO_CRED_CMDLINE_ID:$COCO_CRED_CMDLINE_VALUE"
echo "SEV-SNP direct-boot guest correctly reported confidential virtualization and trusted credentials"

# Offensive test:
#
# - creds_hostile_*: ensure the guest isn't tricked into consuming untrusted/unmeasured credentials.
QEMU_EXTRA=(
    -smbios "type=11,value=io.systemd.credential:$COCO_CRED_SMBIOS_ID=$COCO_CRED_SMBIOS_VALUE"
    -smbios "type=11,value=io.systemd.credential:$COCO_CRED_TRUSTED_ID=$COCO_CRED_SMBIOS_VALUE"
    -fw_cfg "name=opt/io.systemd.credentials/$COCO_CRED_FWCFG_ID,string=$COCO_CRED_FWCFG_VALUE"
)

SYSTEMD_VMSPAWN_QEMU_EXTRA="${QEMU_EXTRA[*]}" \
vmspawn_boot_coco "$MACHINE-hostile" "$COCO_TYPE" "$WORKDIR/hostile" \
    'detect_virt creds_vmspawn creds_hostile_fwcfg creds_hostile_snp_smbios creds_hostile_shadow' \
    --image="$IMAGE_DIR/image.raw" \
    --linux="$IMAGE_DIR/image.vmlinuz" \
    --initrd="$IMAGE_DIR/image.initrd" \
    --set-credential="$COCO_CRED_TRUSTED_ID:$COCO_CRED_TRUSTED_VALUE" \
    selinux=0 systemd.firstboot=no rw
echo "SEV-SNP direct-boot guest correctly ignored the host-injected credentials"
