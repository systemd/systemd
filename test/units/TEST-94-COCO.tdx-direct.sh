#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# TDX, direct kernel boot: launch confidential guests with --linux=/--initrd=.

set -eux
set -o pipefail

# shellcheck source=test/units/TEST-94-COCO/lib.sh
. "$(dirname "$0")"/TEST-94-COCO/lib.sh

if [[ "${COCO_TYPE:?}" != "tdx" ]]; then
    echo "host coco type is '$COCO_TYPE', not tdx, skipping"
    exit 77
fi

IMAGE_DIR="$(vmspawn_images_dir)"
MACHINE="coco-tdx-direct-$$"
WORKDIR="$(mktemp -d)"
mkdir -p "$WORKDIR/honest" "$WORKDIR/hostile"
at_exit() {
    set +e
    jobs -p | xargs -r kill 2>/dev/null
    machinectl terminate "$MACHINE-honest" 2>/dev/null || :
    machinectl terminate "$MACHINE-hostile" 2>/dev/null || :
    rm -rf "$WORKDIR"
}
trap at_exit EXIT

# Honest host, direct boot of a plain kernel image. No boot loader runs, so vmspawn delivers
# credentials via the initrd cpio, which the Linux EFI stub measures into RTMR 2 together with the
# command line. Covers:
#
# - detect_virt: systemd-detect-virt --cvm detects TDX as the CVM type
# - creds_vmspawn: credential transport by vmspawn is working (via the initrd cpio here)
# - creds_cmdline: credential transport via the kernel command line is working (measured into RTMR 2)
vmspawn_boot_coco "$MACHINE-honest" "$COCO_TYPE" "$WORKDIR/honest" \
    'detect_virt creds_vmspawn creds_cmdline' \
    --image="$IMAGE_DIR/image.raw" \
    --linux="$IMAGE_DIR/image.vmlinuz" \
    --initrd="$IMAGE_DIR/image.initrd" \
    --set-credential="$COCO_CRED_TRUSTED_ID:$COCO_CRED_TRUSTED_VALUE" \
    selinux=0 systemd.firstboot=no rw \
    "systemd.set_credential=$COCO_CRED_CMDLINE_ID:$COCO_CRED_CMDLINE_VALUE"
echo "TDX direct-boot guest correctly reported confidential virtualization and trusted credentials"

# Hostile host. Without a boot loader nobody measured the SMBIOS table (the firmware's own SMBIOS
# measurement zeroes the OEM strings), and fw_cfg is never measured, so the guest must ignore
# credentials injected through either channel. Covers:
#
# - creds_hostile_*: ensure the guest isn't tricked into consuming unmeasured credentials.
QEMU_EXTRA=(
    -smbios "type=11,value=io.systemd.credential:$COCO_CRED_SMBIOS_ID=$COCO_CRED_SMBIOS_VALUE"
    -smbios "type=11,value=io.systemd.credential:$COCO_CRED_TRUSTED_ID=$COCO_CRED_SMBIOS_VALUE"
    -fw_cfg "name=opt/io.systemd.credentials/$COCO_CRED_FWCFG_ID,string=$COCO_CRED_FWCFG_VALUE"
)

SYSTEMD_VMSPAWN_QEMU_EXTRA="${QEMU_EXTRA[*]}" \
vmspawn_boot_coco "$MACHINE-hostile" "$COCO_TYPE" "$WORKDIR/hostile" \
    'detect_virt creds_vmspawn creds_hostile_fwcfg creds_hostile_smbios creds_hostile_shadow' \
    --image="$IMAGE_DIR/image.raw" \
    --linux="$IMAGE_DIR/image.vmlinuz" \
    --initrd="$IMAGE_DIR/image.initrd" \
    --set-credential="$COCO_CRED_TRUSTED_ID:$COCO_CRED_TRUSTED_VALUE" \
    selinux=0 systemd.firstboot=no rw
echo "TDX direct-boot guest correctly ignored the host-injected credentials"
