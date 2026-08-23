#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Launch a confidential VM with systemd-vmspawn --coco= and verify the guest reports the expected
# confidential-virtualization type. Runs only on coco-capable hardware: the harness --coco=any flag gates
# the run (skipped otherwise), binds /dev/kvm + the coco device(s) into this boot-mode container, and
# passes the resolved technology via $COCO_TYPE.
#
# The confidential guest boots the same mkosi test image. A one-shot unit injected into the guest checks
# systemd-detect-virt --cvm and reports the verdict via systemd's exit-status notification over vsock
# (SuccessAction=exit): the guest PID1 sends EXIT_STATUS to vmspawn's vmm notify socket and vmspawn exits
# with it.
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
    echo "COCO_TYPE not set (run via the integration harness with --coco), skipping" | tee --append /skipped
    exit 77
fi
echo "Host coco type: $COCO_TYPE"

# The harness binds the guest image read-only at /work/vm-images (the 'vm-images' test option).
IMAGE_DIR=/work/vm-images
if [[ ! -f "$IMAGE_DIR/image.raw" || ! -f "$IMAGE_DIR/image.vmlinuz" || ! -f "$IMAGE_DIR/image.initrd" ]]; then
    echo "guest image not found in $IMAGE_DIR, skipping" | tee --append /skipped
    exit 77
fi
echo "Guest image directory: $IMAGE_DIR"

MACHINE="coco-guest-$$"
WORKDIR="$(mktemp -d)"
at_exit() {
    set +e
    machinectl terminate "$MACHINE" 2>/dev/null || :
    rm -rf "$WORKDIR"
}
trap at_exit EXIT INT TERM

# One-shot unit for the guest: verify systemd-detect-virt --cvm matches the type vmspawn launched.
# Created via the systemd.extra-unit.* credential and pulled into the boot by a multi-user.target drop-in.
GUEST_PASS=123
GUEST_UNIT="$(cat <<'EOF'
[Unit]
Description=coco guest self-check
After=basic.target
SuccessAction=exit
SuccessActionExitStatus=@GUEST_PASS@
FailureAction=exit
FailureActionExitStatus=1
[Service]
Type=oneshot
ExecStart=bash -c 'test "$(systemd-detect-virt --cvm)" = "@COCO_TYPE@"'
EOF
)"
GUEST_UNIT="${GUEST_UNIT//@COCO_TYPE@/$COCO_TYPE}"
GUEST_UNIT="${GUEST_UNIT//@GUEST_PASS@/$GUEST_PASS}"

GUEST_DROPIN="$(cat <<'EOF'
[Unit]
Wants=coco-guest.service
After=coco-guest.service
EOF
)"

# Launch the confidential guest and capture its console output.
# Direct linux boot should work on all coco platforms (the only boot path supported by SNP).
vmspawn_rc=0
timeout -k 30 300 systemd-vmspawn \
    --machine="$MACHINE" \
    --coco="$COCO_TYPE" \
    --ram=1G \
    --ephemeral \
    --image="$IMAGE_DIR/image.raw" \
    --linux="$IMAGE_DIR/image.vmlinuz" \
    --initrd="$IMAGE_DIR/image.initrd" \
    --tpm=no \
    --console=read-only \
    --set-credential="systemd.extra-unit.coco-guest.service:$GUEST_UNIT" \
    --set-credential="systemd.unit-dropin.multi-user.target:$GUEST_DROPIN" \
    selinux=0 systemd.firstboot=no rw \
    2>&1 | tee "$WORKDIR/console.log" || vmspawn_rc="${PIPESTATUS[0]}"
if [[ "$vmspawn_rc" -eq 124 || "$vmspawn_rc" -eq 137 ]]; then
    echo "systemd-vmspawn was killed by timeout (exit $vmspawn_rc)" >&2
    cat "$WORKDIR/console.log" >&2
    exit 1
elif [[ "$vmspawn_rc" -ne "$GUEST_PASS" ]]; then
    echo "guest coco self-check did not pass: vmspawn exit $vmspawn_rc (expected $GUEST_PASS)" >&2
    cat "$WORKDIR/console.log" >&2
    exit 1
fi
echo "Guest correctly reported confidential virtualization: $COCO_TYPE"

touch /testok
