#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Exercises the software TPM fallback (systemd-tpm2-swtpm.service) across a reboot. The VM boots in EFI mode
# without a hardware/firmware TPM and with "systemd.tpm2_software_fallback=yes" (see the test's meson.build),
# so systemd-tpm2-generator manufactures a software TPM on the ESP in the initrd and chainloads swtpm.
#
#   boot 0: the TPM is manufactured in the initrd; seal a secret to it and stash the blob.
#   boot 1: the TPM state persisted on the ESP across the reboot, so the secret still unseals.
#
# See systemd-tpm2-swtpm.service(8).

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

CRED=/var/lib/systemd-tpm2-swtpm-test.cred
PLAINTEXT="swtpm round-trip"

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
    systemctl is-active systemd-tpm2-swtpm.service
    timeout 30 bash -c 'until [[ -c /dev/tpmrm0 ]]; do sleep 1; done'
    test -c /dev/tpm0
    # No firmware TPM here, so has-tpm2 reports "partial"; assert the software driver is present.
    assert_in '\+driver' "$(systemd-analyze has-tpm2 || :)"
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
        touch /testok
        ;;
    *)
        assert_not_reached
        ;;
esac
