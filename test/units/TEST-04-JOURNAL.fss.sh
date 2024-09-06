#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Forward Secure Sealing

if ! journalctl --version | grep -qF +GCRYPT; then
    echo "Built without gcrypt, skipping the FSS tests"
    exit 0
fi

journalctl --force --setup-keys --interval=2 |& tee /tmp/fss
FSS_VKEY="$(sed -rn '/([a-f0-9]{6}\-){3}[a-f0-9]{6}\/[a-f0-9]+\-[a-f0-9]+/p' /tmp/fss)"
[[ -n "$FSS_VKEY" ]]

# Generate some buzz in the journal and wait until the FSS key is changed
# at least once
systemd-cat cat /etc/os-release
sleep 4
# Seal the journal
journalctl --rotate
# Verification should fail without a valid FSS key
(! journalctl --verify)
(! journalctl --verify --verify-key="")
(! journalctl --verify --verify-key="000000-000000-000000-000000/00000000-00000")
# FIXME: ignore --verify result until #27532 is resolved
journalctl --verify --verify-key="$FSS_VKEY" || :

# Sealing + systemd-journal-remote
/usr/lib/systemd/systemd-journal-remote --getter="journalctl -n 5 -o export" \
                                        --split-mode=none \
                                        --seal=yes \
                                        --output=/tmp/sealed.journal
(! journalctl --file=/tmp/sealed.journal --verify)
(! journalctl --file=/tmp/sealed.journal --verify --verify-key="")
(! journalctl --file=/tmp/sealed.journal --verify --verify-key="000000-000000-000000-000000/00000000-00000")
# FIXME: ignore --verify result until #27532 is resolved
journalctl --file=/tmp/sealed.journal --verify --verify-key="$FSS_VKEY" || :
rm -f /tmp/sealed.journal

# Return back to a journal without FSS
rm -fv "/var/log/journal/$(</etc/machine-id)/fss"
journalctl --rotate --vacuum-size=1
# FIXME: ignore --verify result until #27532 is resolved
journalctl --verify || :
