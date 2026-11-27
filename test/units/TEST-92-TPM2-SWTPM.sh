#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Exercises the software TPM fallback (systemd-tpm2-swtpm.service) across reboots. The VM boots in EFI mode
# without a hardware/firmware TPM and with "rd.systemd.tpm2_software_fallback=yes" (see the test's meson.build),
# so systemd-tpm2-generator manufactures a software TPM on the ESP in the initrd and chainloads swtpm. It also
# sets "systemd.tpm2_measured_os=1", so NvPCRs get initialized in the initrd, which is checked in every boot.
#
#   boot 0: the TPM is manufactured in the initrd; seal a secret to it and stash the blob. Then restart the
#           service and check that the vTPM proxy device survived in the fdstore. Also check that a volume
#           created by systemd-repart with Encrypt=tpm2, or enrolled by systemd-cryptenroll, can be unlocked.
#   boot 1: the TPM state persisted on the ESP across the reboot, so the secret still unseals. Then mimic a
#           manufacture that was interrupted before it completed (drop everything but the config files, so the
#           ".manufactured" marker is gone) and reboot.
#   boot 2: setup_swtpm() must notice the missing marker and re-manufacture, rather than mistaking the
#           leftover config files for a complete TPM and starting swtpm against a stateless directory.
#
# In every boot the vTPM proxy device must have been allocated exactly once (in the initrd) and then been
# handed over to the host via the service's fdstore, so that it is still /dev/tpm0.
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

# The initrd must stop swtpm without issuing TPM2_Shutdown() for the handoff to work.
swtpm_capabilities="$(swtpm chardev --tpm2 --print-capabilities)"
if ! grep -F '"flags-opt-disable-auto-shutdown"' <<<"$swtpm_capabilities" >/dev/null; then
    echo "swtpm lacks disable-auto-shutdown support, skipping the test" | tee --append /skipped
    exit 77
fi

assert_swtpm_up() {
    local n

    systemctl is-active systemd-tpm2-swtpm.service

    # The vTPM proxy device allocated in the initrd is kept in the fdstore across the initrd→host
    # transition, hence it is never released and reallocated and keeps its device number.
    TPM2_DEVICE=/dev/tpmrm0
    udevadm wait --timeout=30 --settle "$TPM2_DEVICE" /dev/tpm0
    assert_eq "$(compgen -G '/sys/class/tpmrm/tpmrm*')" /sys/class/tpmrm/tpmrm0
    assert_eq "$(systemctl show -P NFileDescriptorStore systemd-tpm2-swtpm.service)" 1
    systemd-analyze fdstore systemd-tpm2-swtpm.service
    assert_in 'vtpm-proxy' "$(systemd-analyze fdstore systemd-tpm2-swtpm.service)"
    # The device number is recorded so that systemd-tpm2-generator recognizes the device as ours after the
    # initrd→host transition.
    assert_eq "$(cat /run/systemd/swtpm/devno)" "$(cat /sys/devices/virtual/tpm/tpm0/dev)"

    # The device must have been allocated once (in the initrd), and been reused after the transition.
    # Match the syslog identifier because journald can attribute initrd messages to init.scope.
    journalctl --sync
    n="$(journalctl -q -b -t systemd-tpm2-swtpm -o cat --grep '^Allocated vTPM proxy device' | wc -l || :)"
    assert_eq "$n" 1
    n="$(journalctl -q -b -t systemd-tpm2-swtpm -o cat --grep '^Reusing vTPM proxy device from file descriptor store' | wc -l || :)"
    assert_ge "$n" 1

    # No firmware TPM here, so has-tpm2 reports "partial"; assert the software driver is present.
    assert_in '\+driver' "$(systemd-analyze has-tpm2 || :)"
}

# Restart swtpm and check that the vTPM proxy device stays around while it is stopped and is reused after.
check_swtpm_restart() {
    local ino

    ino="$(stat -L -c %i /sys/class/tpm/tpm0)"

    systemctl stop systemd-tpm2-swtpm.service
    test -e /sys/class/tpm/tpm0
    assert_eq "$(systemctl show -P NFileDescriptorStore systemd-tpm2-swtpm.service)" 1
    assert_eq "$(cat /run/systemd/swtpm/devno)" "$(cat /sys/devices/virtual/tpm/tpm0/dev)"

    systemctl start systemd-tpm2-swtpm.service
    systemctl is-active systemd-tpm2-swtpm.service
    # Still the very same kernel device (sysfs inode numbers are not reused right away)
    assert_eq "$(stat -L -c %i /sys/class/tpm/tpm0)" "$ino"
    assert_eq "$(compgen -G '/sys/class/tpmrm/tpmrm*')" /sys/class/tpmrm/tpmrm0
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

# The same for a TPM2 slot enrolled by systemd-cryptenroll, which also picks up the PCR public key on its
# own.
test_cryptenroll_tpm2() {
    local image passphrase

    test -e /run/systemd/tpm2-pcr-public-key.pem

    image="$(mktemp)"
    passphrase="$(mktemp)"
    echo -n passphrase >"$passphrase"
    truncate -s 20M "$image"
    cryptsetup luksFormat -q --pbkdf pbkdf2 --pbkdf-force-iterations 1000 --use-urandom \
        "$image" "$passphrase"
    PASSWORD=passphrase systemd-cryptenroll --tpm2-device="$TPM2_DEVICE" "$image"
    systemd-cryptsetup attach swtpm-cryptenroll "$image" - tpm2-device="$TPM2_DEVICE",headless=yes
    systemd-cryptsetup detach swtpm-cryptenroll
    rm -f "$image" "$passphrase"
}

# With systemd.tpm2_measured_os=1, systemd-tpm2-setup-early.service initializes the NvPCRs in the initrd. The
# signed init policy can't be satisfied as long as the UKI isn't measured into PCR 11, hence this has to
# fall back to the PCR init policy. Afterwards, extending an NvPCR must work.
test_nvpcr() {
    local before after

    systemd-analyze condition ConditionSecurity=measured-os
    test -e /run/systemd/tpm2-pcr-public-key.pem
    test -e /run/systemd/nvpcr/verity.auth

    before="$(systemd-analyze nvpcrs verity --json=short | jq --exit-status --raw-output '.[0].value')"
    /usr/lib/systemd/systemd-pcrextend --nvpcr=verity swtpm-test
    after="$(systemd-analyze nvpcrs verity --json=short | jq --exit-status --raw-output '.[0].value')"
    assert_neq "$before" "$after"
}

case "$REBOOT_COUNT" in
    0)
        assert_swtpm_up
        test_nvpcr
        # Seal a secret to the software TPM and keep the blob for the next boot.
        echo -n "$PLAINTEXT" >/tmp/swtpm-plaintext
        systemd-creds --tpm2-device="$TPM2_DEVICE" encrypt --name= --with-key=tpm2 /tmp/swtpm-plaintext "$CRED"
        systemd-creds --tpm2-device="$TPM2_DEVICE" decrypt --name= "$CRED" - | cmp /tmp/swtpm-plaintext -
        check_swtpm_restart
        systemd-creds --tpm2-device="$TPM2_DEVICE" decrypt --name= "$CRED" - | cmp /tmp/swtpm-plaintext -
        test_repart_encrypt_tpm2
        test_cryptenroll_tpm2
        systemctl_final reboot
        exec sleep infinity
        ;;
    1)
        assert_swtpm_up
        # The NV indexes persisted from the previous boot, so this checks that they are initialized again.
        test_nvpcr
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
        test_nvpcr
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
