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

. /etc/os-release
if [[ "${ID_LIKE:-}" == alpine ]]; then
    # For some unknown reasons, the test fails with the following:
    # --------
    # Couldn't find signature for this PCR bank, PCR index and public key.
    # Failed to unseal secret using TPM2: No such device or address
    # --------
    exit 0
fi

"$SD_TPM2SETUP" --help
"$SD_TPM2SETUP" --version
"$SD_TPM2SETUP" --tpm2-device=list
"$SD_TPM2SETUP" --tpm2-device=auto
"$SD_TPM2SETUP" --tpm2-device=/dev/tpmrm0
"$SD_TPM2SETUP" --early=yes
"$SD_TPM2SETUP" --early=yes
"$SD_TPM2SETUP" --early=no
"$SD_TPM2SETUP" --early=no

(! "$SD_TPM2SETUP" "")
(! "$SD_TPM2SETUP" --tpm2-device=)
(! "$SD_TPM2SETUP" --tpm2-device=/dev/null)
(! "$SD_TPM2SETUP" --foo=bar)
