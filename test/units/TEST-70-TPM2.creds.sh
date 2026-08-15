#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

export SYSTEMD_LOG_LEVEL=debug

at_exit() {
	rm -f /tmp/testdata /tmp/testdata.encrypted
}

trap at_exit EXIT

# Ensure that sandboxing doesn't stop creds from being accessible
echo "test" >/tmp/testdata
systemd-creds encrypt /tmp/testdata /tmp/testdata.encrypted --with-key=tpm2
# LoadCredentialEncrypted
systemd-run -p PrivateDevices=yes -p LoadCredentialEncrypted=testdata.encrypted:/tmp/testdata.encrypted --pipe --wait systemd-creds cat testdata.encrypted | cmp - /tmp/testdata
# SetCredentialEncrypted
systemd-run -p PrivateDevices=yes -p SetCredentialEncrypted=testdata.encrypted:"$(cat /tmp/testdata.encrypted)" --pipe --wait systemd-creds cat testdata.encrypted | cmp - /tmp/testdata
