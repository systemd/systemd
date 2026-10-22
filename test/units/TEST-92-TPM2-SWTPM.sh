#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Exercises the software TPM fallback (systemd-tpm2-swtpm.service) across reboots. The VM boots in EFI mode
# without a hardware/firmware TPM and with "systemd.tpm2_software_fallback=yes" (see the test's meson.build),
# so systemd-tpm2-generator manufactures a software TPM on the ESP in the initrd and chainloads swtpm.
#
#   boot 0: the TPM is manufactured in the initrd; seal a secret to it and stash the blob. Also check that
#           a volume created by systemd-repart with Encrypt=tpm2 can be unlocked.
#   boot 1: the TPM state persisted on the ESP across the reboot, so the secret still unseals. Then mimic a
#           manufacture that was interrupted before it completed (drop everything but the config files, so the
#           ".manufactured" marker is gone) and reboot.
#   boot 2: setup_swtpm() must notice the missing marker and re-manufacture, rather than mistaking the
#           leftover config files for a complete TPM and starting swtpm against a stateless directory.
#
# See systemd-tpm2-swtpm.service(8).

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

CRED=/var/lib/systemd-tpm2-swtpm-test.cred
PLAINTEXT="swtpm round-trip"
# Marker (SWTPM_MANUFACTURED_MARKER) that manufacture_swtpm() indicates completion with.
MARKER=.manufactured
TPM2_DEVICE=

if [[ -n "${ASAN_OPTIONS:-}" ]]; then
    # swtpm_setup is not built with sanitizers, but does NSS lookups that pull in the ASan-instrumented
    # libnss_systemd.so, which aborts with "ASan runtime does not come first". Skip under sanitizers.
    echo "swtpm_setup does not work under sanitizers, skipping the test" | tee --append /skipped
    exit 77
fi

if [[ ! -x /usr/lib/systemd/systemd-tpm2-swtpm ]] || ! command -v swtpm >/dev/null || [[ ! -d /sys/firmware/efi ]]; then
    echo "Software TPM prerequisites missing, skipping the test" | tee --append /skipped
    exit 77
fi

assert_swtpm_up() {
    local deadline tpm_device tpm_index tpmrm_device tpmrm_devices

    systemctl is-active systemd-tpm2-swtpm.service

    deadline=$((SECONDS + 30))
    while (( SECONDS < deadline )); do
        mapfile -t tpmrm_devices < <(compgen -G '/sys/class/tpmrm/tpmrm*' || :)
        ((${#tpmrm_devices[@]} == 1)) && break
        sleep .1
    done
    assert_eq "${#tpmrm_devices[@]}" 1

    # The old initrd device number may still be reserved when the host swtpm starts, so do not assume tpm0.
    tpmrm_device="${tpmrm_devices[0]##*/}"
    tpm_index="${tpmrm_device#tpmrm}"
    TPM2_DEVICE="/dev/$tpmrm_device"
    tpm_device="/dev/tpm$tpm_index"

    udevadm wait --timeout=30 --settle "$TPM2_DEVICE" "$tpm_device"
    # No firmware TPM here, so has-tpm2 reports "partial"; assert the software driver is present.
    assert_in '\+driver' "$(systemd-analyze has-tpm2 || :)"
}

# Locate swtpm's state directory on the ESP.
swtpm_state_dir() {
    local d
    for d in /boot/loader/swtpm /efi/loader/swtpm; do
        [[ -d "$d" ]] && { echo "$d"; return 0; }
    done
    return 1
}

# An Encrypt=tpm2 volume created by systemd-repart must be unlockable with the software TPM. Binding to the
# signed PCR 11 policy would break this as long as the UKI isn't measured into PCR 11. The PCR public key
# must exist, as otherwise there would be nothing to bind to and this would test nothing.
test_repart_encrypt_tpm2() {
    local defs device image

    test -e /run/systemd/tpm2-pcr-public-key.pem

    defs="$(mktemp --directory)"
    image="$(mktemp --dry-run)"
    cat >"$defs/50-root.conf" <<EOF
[Partition]
Type=root
Format=ext4
Encrypt=tpm2
EOF
    systemd-repart --tpm2-device="$TPM2_DEVICE" --definitions="$defs" --empty=create --size=80M "$image"
    device="$(systemd-dissect --attach "$image")"
    udevadm wait --settle --timeout=10 "${device}p1"
    systemd-cryptsetup attach swtpm-repart "${device}p1" - tpm2-device="$TPM2_DEVICE",headless=yes
    systemd-cryptsetup detach swtpm-repart
    systemd-dissect --detach "$device"
    rm -rf "$defs" "$image"
}

case "$REBOOT_COUNT" in
    0)
        assert_swtpm_up
        # Seal a secret to the software TPM and keep the blob for the next boot.
        echo -n "$PLAINTEXT" >/tmp/swtpm-plaintext
        systemd-creds --tpm2-device="$TPM2_DEVICE" encrypt --name= --with-key=tpm2 /tmp/swtpm-plaintext "$CRED"
        systemd-creds --tpm2-device="$TPM2_DEVICE" decrypt --name= "$CRED" - | cmp /tmp/swtpm-plaintext -
        test_repart_encrypt_tpm2
        systemctl_final reboot
        exec sleep infinity
        ;;
    1)
        assert_swtpm_up
        # Persistence: the TPM state survived the reboot on the ESP, so the blob still unseals.
        echo -n "$PLAINTEXT" >/tmp/swtpm-plaintext
        systemd-creds --tpm2-device="$TPM2_DEVICE" decrypt --name= "$CRED" - | cmp /tmp/swtpm-plaintext -

        # Mimic a manufacture interrupted after swtpm began writing TPM state but before the marker: stop
        # swtpm, drop everything except the three config files, then leave a partial/corrupt state file
        # behind. swtpm_setup --not-overwrite would refuse to recreate that, so recovery must clear it first.
        statedir="$(swtpm_state_dir)"
        systemctl stop systemd-tpm2-swtpm.service
        find "$statedir" -mindepth 1 -maxdepth 1 -type f \
             ! -name swtpm-localca.conf ! -name swtpm-localca.options ! -name swtpm_setup.conf -delete
        echo "corrupt" >"$statedir/tpm2-00.permall"
        test -e "$statedir/swtpm_setup.conf"
        test ! -e "$statedir/$MARKER"
        systemctl_final reboot
        exec sleep infinity
        ;;
    2)
        # setup_swtpm() must have re-manufactured instead of trusting the leftover config files: the marker is
        # back and swtpm_setup re-ran swtpm_localca, recreating issuer-certificate.pem. The TPM must also work.
        # Regression test for keying re-manufacture off an incomplete state directory.
        assert_swtpm_up
        statedir="$(swtpm_state_dir)"
        test -e "$statedir/$MARKER"
        test -e "$statedir/issuer-certificate.pem"
        echo -n "$PLAINTEXT" >/tmp/swtpm-plaintext
        systemd-creds --tpm2-device="$TPM2_DEVICE" encrypt --name= --with-key=tpm2 /tmp/swtpm-plaintext /tmp/swtpm-new.cred
        systemd-creds --tpm2-device="$TPM2_DEVICE" decrypt --name= /tmp/swtpm-new.cred - | cmp /tmp/swtpm-plaintext -
        touch /testok
        ;;
    *)
        assert_not_reached
        ;;
esac
