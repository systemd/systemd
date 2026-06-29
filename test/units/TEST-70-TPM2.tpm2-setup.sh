#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

export SYSTEMD_LOG_LEVEL=debug
SD_TPM2SETUP="/usr/lib/systemd/systemd-tpm2-setup"

if [[ ! -x "${SD_TPM2SETUP:?}" ]]; then
    echo "$SD_TPM2SETUP not found, skipping the test"
    exit 0
fi

# systemd-tpm2-setup returns EX_UNAVAILABLE rather than 0 when it cannot set something up but this
# is still considered success. This happens at the moment because there is no EK certificate in
# QEMU guests.
run_tpm2_setup() {
    local rc=0
    "$SD_TPM2SETUP" "$@" || rc=$?
    [[ "$rc" -eq 0 || "$rc" -eq 69 ]]
}

"$SD_TPM2SETUP" --help
"$SD_TPM2SETUP" --version
"$SD_TPM2SETUP" --tpm2-device=list
run_tpm2_setup --tpm2-device=auto
run_tpm2_setup --tpm2-device=/dev/tpmrm0
run_tpm2_setup --early=yes
run_tpm2_setup --early=yes
run_tpm2_setup --early=no
run_tpm2_setup --early=no

(! "$SD_TPM2SETUP" "")
(! "$SD_TPM2SETUP" --tpm2-device=)
(! "$SD_TPM2SETUP" --tpm2-device=/dev/null)
(! "$SD_TPM2SETUP" --foo=bar)
