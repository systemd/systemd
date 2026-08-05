#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Launch a confidential VM with systemd-vmspawn --coco= and verify the guest reports the expected
# confidential-virtualization type. Runs only on coco-capable hardware: the harness --coco=any flag gates
# the run (skipped otherwise), binds /dev/kvm + the coco device(s) into this boot-mode container, and
# passes the resolved technology via $COCO_TYPE.
#
# The confidential guest boots the same mkosi test image. A one-shot unit injected into the guest prints
# its detected coco type to the console and powers off; we grep the captured console for it.
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

if [[ -v ASAN_OPTIONS ]]; then
    echo "vmspawn launches QEMU which doesn't work under ASan, skipping" | tee --append /skipped
    exit 77
fi

if ! command -v systemd-vmspawn >/dev/null 2>&1; then
    echo "systemd-vmspawn not found, skipping" | tee --append /skipped
    exit 77
fi

if ! find_qemu_binary; then
    echo "QEMU not found, skipping" | tee --append /skipped
    exit 77
fi

# The integration-test-wrapper resolves the host's coco technology on the
# bare-metal host (where /sys/module is readable) and passes it via $COCO_TYPE.
if [[ -z "${COCO_TYPE:-}" ]]; then
    echo "COCO_TYPE not set (run via the integration harness with --coco, or set it for manual runs), skipping" | tee --append /skipped
    exit 77
fi
echo "Host coco type: $COCO_TYPE"

# Locate the guest image. Under the integration harness it's bound read-only at /vm-images (see the
# 'vm-images' test option). A manual interactive boot instead has the build tree at /work/src via
# RuntimeBuildSources.
OUT=""
for d in /vm-images /work/src/build/mkosi.output /work/build/mkosi.output; do
    if [[ -f "$d/image.raw" && -f "$d/image.vmlinuz" && -f "$d/image.initrd" ]]; then
        OUT="$d"
        break
    fi
done
if [[ -z "$OUT" ]]; then
    echo "Could not locate the guest image (need image.raw, image.vmlinuz, image.initrd), skipping" | tee --append /skipped
    exit 77
fi
echo "Guest image directory: $OUT"

WORKDIR="$(mktemp -d)"
at_exit() {
    set +e
    rm -rf "$WORKDIR"
}
trap at_exit EXIT

# One-shot unit for the guest: report the detected coco type on the console, then power off. Created via
# the systemd.extra-unit.* credential and pulled into the boot by a multi-user.target drop-in, mirroring
# how the integration harness injects its own units.
GUEST_UNIT="$(cat <<'EOF'
[Unit]
Description=coco guest self-check
After=basic.target
[Service]
Type=oneshot
StandardOutput=journal+console
ExecStart=bash -c 'echo "COCO-GUEST-CVM=$(systemd-detect-virt --cvm)"'
ExecStopPost=systemctl poweroff --force --no-block
EOF
)"

GUEST_DROPIN="$(cat <<'EOF'
[Unit]
Wants=coco-guest.service
After=coco-guest.service
EOF
)"

# Launch the confidential guest and capture its console output.
# Direct linux boot should work on all coco platforms (the only boot path supported by SNP).
timeout -k 30 300 systemd-vmspawn \
    --machine="coco-guest-$$" \
    --coco="$COCO_TYPE" \
    --ram=1G \
    --ephemeral \
    --image="$OUT/image.raw" \
    --linux="$OUT/image.vmlinuz" \
    --initrd="$OUT/image.initrd" \
    --tpm=no \
    --console=read-only \
    --set-credential="systemd.extra-unit.coco-guest.service:$GUEST_UNIT" \
    --set-credential="systemd.unit-dropin.multi-user.target:$GUEST_DROPIN" \
    selinux=0 systemd.firstboot=no rw \
    2>&1 | tee "$WORKDIR/console.log" || :

# The guest must report the same confidential-virtualization type the host offered.
grep -aFq "COCO-GUEST-CVM=$COCO_TYPE" "$WORKDIR/console.log"
echo "Guest correctly reported confidential virtualization: $COCO_TYPE"

touch /testok
