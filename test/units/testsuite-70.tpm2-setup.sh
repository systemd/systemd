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

# Run this, just to get sanitizer coverage. The tools should be idempotent, hence run the multiple times.
"$SD_TPM2SETUP" --early=yes
"$SD_TPM2SETUP" --early=yes
"$SD_TPM2SETUP" --early=no
"$SD_TPM2SETUP" --early=no
