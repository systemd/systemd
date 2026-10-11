#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Test that systemd-dissect and systemd-sysext unlock a DDI whose LUKS partition carries a "systemd-tpm2"
# LUKS2 token via the local TPM2, without any passphrase, and that systemd-dissect falls back to a passphrase
# if the token does not match the current system state (DISSECT_IMAGE_TPM2_UNLOCK in dissect-image.c).
#
# The images' LUKS partitions are bound to PCR 16 (the resettable "debug" PCR nothing else in this test
# depends on), so that extending that PCR afterwards invalidates the tokens. The PCR is reset on exit.
#
# Note that there is deliberately no "no passphrase + non-matching token must fail" case for systemd-dissect:
# without a matching TPM2 token and without $PASSWORD, it asks for a passphrase via ask_password_auto() with
# an infinite timeout, i.e. in this non-interactive environment it would block on the password agent
# forever. The fallback is instead verified via the debug log of a successful $PASSWORD unlock.

if ! tpm_has_pcr sha256 16; then
    echo "TPM2 has no sha256 PCR 16, skipping"
    exit 77
fi

export SYSTEMD_LOG_LEVEL=debug

WORKDIR="$(mktemp -d /tmp/dissect-tpm2.XXXXXXXXXX)"
IMAGE="$WORKDIR/image.raw"
IMAGE_REPART="$WORKDIR/image-repart.raw"
MNT="$WORKDIR/mnt"
LOG="$WORKDIR/dissect.log"
# Fake root for systemd-sysext --root=, so that the real /usr is left alone
SYSEXT_ROOT="$WORKDIR/root"
SYSEXT_NAME="dissect-tpm2"
DEVICE=""

at_exit() {
    set +e

    if mountpoint -q "$MNT"; then
        systemd-dissect --umount "$MNT"
    fi
    if [[ -n "$DEVICE" ]]; then
        systemd-dissect --detach "$DEVICE"
    fi
    if [[ -d "$SYSEXT_ROOT" ]]; then
        systemd-sysext --root="$SYSEXT_ROOT" unmerge
    fi

    rm -rf "$WORKDIR"

    # Undo the PCR extension below, for the subtests that run after this one
    tpm2_pcrreset 16
}

trap at_exit EXIT

# All mounts are wrapped in timeout(1): should TPM2 unlocking not work, systemd-dissect would otherwise
# block on the password agent (see above) instead of failing the test.
dissect_mount() {
    if ! timeout --kill-after=10 120 systemd-dissect --mount "$IMAGE" "$MNT" &>"$LOG"; then
        cat "$LOG"
        return 1
    fi
    test -f "$MNT/usr/lib/os-release"
    systemd-dissect --umount "$MNT"
}

# Enroll the TPM2 into the LUKS partition of the specified image, bound to PCR 16
enroll_tpm2() {
    local image="${1:?}"

    DEVICE="$(systemd-dissect --attach "$image")"
    udevadm wait --settle --timeout=10 "$DEVICE"p1
    # Use --tpm2-public-key= to suppress auto-loading any PCR public key from the host
    systemd-cryptenroll --unlock-key-file="$WORKDIR/passphrase" --tpm2-device=auto --tpm2-public-key= --tpm2-pcrs=16 "$DEVICE"p1
    systemd-dissect --detach "$DEVICE"
    DEVICE=""
}

mkdir -p "$WORKDIR/defs" "$MNT"
echo -n passphrase >"$WORKDIR/passphrase"
# Avoid "has 0644 mode that is too permissive" messages
chmod 0600 "$WORKDIR/passphrase"

# Build a DDI with a passphrase-encrypted root partition, then enroll the TPM2 into it with
# systemd-cryptenroll, i.e. the way such an image would be prepared by hand today.
cat >"$WORKDIR/defs/root.conf" <<EOF
[Partition]
Type=root
Format=ext4
CopyFiles=/usr/lib/os-release:/usr/lib/os-release
Encrypt=key-file
EOF

systemd-repart --definitions="$WORKDIR/defs" \
               --empty=create \
               --size=80M \
               --dry-run=no \
               --offline=no \
               --key-file="$WORKDIR/passphrase" \
               "$IMAGE"

systemd-dissect --validate --image-policy=root=encrypted "$IMAGE"
enroll_tpm2 "$IMAGE"

# 1. No passphrase at all: must be unlocked via the TPM2 token
dissect_mount
grep -q "Automatically discovered security TPM2 token unlocks volume" "$LOG"
grep -q "Completed TPM2 key unsealing" "$LOG"

# 2. systemd-sysext never asks for a passphrase, so for it the TPM2 token is the only way in. Build a
#    system extension image the same way and merge it into a fake root.
mkdir -p "$WORKDIR/ext/usr/lib/extension-release.d" "$SYSEXT_ROOT/usr/lib" "$SYSEXT_ROOT/var/lib/extensions"
echo "ID=_any" >"$WORKDIR/ext/usr/lib/extension-release.d/extension-release.$SYSEXT_NAME"
touch "$WORKDIR/ext/usr/lib/$SYSEXT_NAME-marker"
echo "ID=testtest" >"$SYSEXT_ROOT/usr/lib/os-release"

cat >"$WORKDIR/defs/root.conf" <<EOF
[Partition]
Type=root
Format=ext4
CopyFiles=$WORKDIR/ext:/
Encrypt=key-file
EOF

systemd-repart --definitions="$WORKDIR/defs" \
               --empty=create \
               --size=80M \
               --dry-run=no \
               --offline=no \
               --key-file="$WORKDIR/passphrase" \
               "$SYSEXT_ROOT/var/lib/extensions/$SYSEXT_NAME.raw"

enroll_tpm2 "$SYSEXT_ROOT/var/lib/extensions/$SYSEXT_NAME.raw"

systemd-sysext --root="$SYSEXT_ROOT" merge
test -f "$SYSEXT_ROOT/usr/lib/$SYSEXT_NAME-marker"
systemd-sysext --root="$SYSEXT_ROOT" unmerge
test ! -f "$SYSEXT_ROOT/usr/lib/$SYSEXT_NAME-marker"

# 3. TPM2 unlocking turned off via the environment, passphrase supplied: must use the passphrase keyslot
#    and never touch the TPM2
SYSTEMD_DISSECT_TPM2_UNLOCK=0 PASSWORD=passphrase dissect_mount
(! grep -q "TPM2 key unsealing" "$LOG")

# 4. Invalidate the PCR policy: the tokens no longer match, the passphrase must be used instead
tpm2_pcrextend 16:sha256=0000000000000000000000000000000000000000000000000000000000000000
PASSWORD=passphrase dissect_mount
grep -q "TPM2 token 0 does not match current system state, skipping" "$LOG"
grep -q "Unable to unlock LUKS device via TPM2, ignoring" "$LOG"

# 5. A token written by systemd-repart's Encrypt=tpm2 (not bound to any PCR) must be consumable, too
cat >"$WORKDIR/defs/root.conf" <<EOF
[Partition]
Type=root
Format=ext4
CopyFiles=/usr/lib/os-release:/usr/lib/os-release
Encrypt=tpm2
EOF

# Use --tpm2-public-key-pcrs= to suppress auto-loading of the system PCR public key
systemd-repart --definitions="$WORKDIR/defs" \
               --empty=create \
               --size=80M \
               --dry-run=no \
               --offline=no \
               --tpm2-device=auto \
               --tpm2-public-key-pcrs= \
               --tpm2-pcrs= \
               "$IMAGE_REPART"

IMAGE="$IMAGE_REPART" dissect_mount
grep -q "Completed TPM2 key unsealing" "$LOG"
