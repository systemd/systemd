#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Exercises the software TPM fallback (systemd-tpm2-swtpm.service) across reboots. The VM boots in EFI mode
# without a hardware/firmware TPM and with "systemd.tpm2_software_fallback=yes" (see the test's meson.build),
# so systemd-tpm2-generator manufactures a software TPM on the ESP in the initrd and chainloads swtpm.
#
#   boot 0: the TPM is manufactured in the initrd; seal a secret to it and stash the blob.
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

if [[ ! -x /usr/lib/systemd/systemd-tpm2-swtpm ]] || ! command -v swtpm >/dev/null || [[ ! -d /sys/firmware/efi ]]; then
    echo "Software TPM prerequisites missing, skipping test."
    touch /testok
    exit 0
fi

assert_swtpm_up() {
    systemctl is-active systemd-tpm2-swtpm.service
    timeout 30 bash -c 'until [[ -c /dev/tpmrm0 ]]; do sleep 1; done'
    test -c /dev/tpm0
    # No firmware TPM here, so has-tpm2 reports "partial"; assert the software driver is present.
    assert_in '\+driver' "$(systemd-analyze has-tpm2 || :)"
}

# Locate swtpm's state directory on the ESP (it holds the marker once fully manufactured).
swtpm_state_dir() {
    local d
    for d in /boot/loader/swtpm /efi/loader/swtpm; do
        [[ -e "$d/$MARKER" ]] && { echo "$d"; return 0; }
    done
    return 1
}

case "$REBOOT_COUNT" in
    0)
        assert_swtpm_up
        # Seal a secret to the software TPM and keep the blob for the next boot.
        echo -n "$PLAINTEXT" >/tmp/swtpm-plaintext
        systemd-creds encrypt --name= --with-key=tpm2 /tmp/swtpm-plaintext "$CRED"
        systemd-creds decrypt --name= "$CRED" - | cmp /tmp/swtpm-plaintext -
        systemctl_final reboot
        exec sleep infinity
        ;;
    1)
        assert_swtpm_up
        # Persistence: the TPM state survived the reboot on the ESP, so the blob still unseals.
        echo -n "$PLAINTEXT" >/tmp/swtpm-plaintext
        systemd-creds decrypt --name= "$CRED" - | cmp /tmp/swtpm-plaintext -

        # Mimic an interrupted manufacture: stop swtpm, then drop everything except the three config files.
        # The directory is then non-empty yet holds neither the marker nor any TPM state.
        statedir="$(swtpm_state_dir)"
        systemctl stop systemd-tpm2-swtpm.service
        find "$statedir" -mindepth 1 -maxdepth 1 \
             ! -name swtpm-localca.conf ! -name swtpm-localca.options ! -name swtpm_setup.conf -delete
        test -e "$statedir/swtpm_setup.conf"
        test ! -e "$statedir/$MARKER"
        test ! -e "$statedir/tpm2-00.permall"
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
        systemd-creds encrypt --name= --with-key=tpm2 /tmp/swtpm-plaintext /tmp/swtpm-new.cred
        systemd-creds decrypt --name= /tmp/swtpm-new.cred - | cmp /tmp/swtpm-plaintext -
        touch /testok
        ;;
    *)
        assert_not_reached
        ;;
esac
