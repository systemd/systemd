#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux

# ensure /var/log/journal does not exist
rm -rf /var/log/journal

# first test is to make sure that /var/log/journal is not created
# by starting a new journal namespace if the journald config has
# Storage=auto
cat << EOF > /etc/systemd/journald@foobar.conf
[Journal]
Storage=auto
EOF

systemd-run --wait -p LogNamespace=foobar echo "hello world"

if [[ -d /var/log/journal ]]; then
    echo "/var/log/journal was created with Storage=auto" >/failed
    exit 1
fi

# second test is now making sure that the folder for the namespace
# is correctly created if /var/log/journal exists
# expect /var/log/journal/%m.foobar
mkdir -p /var/log/journal

systemd-run --wait -p LogNamespace=foobar echo "hello world"

MACHINE_ID=$(cat /etc/machine-id)
if ! [[ -d "/var/log/journal/$MACHINE_ID.foobar" ]]; then
    echo "/var/log/journal/$MACHINE_ID.foobar did not get created" >/failed
    exit 1
fi

echo OK >/testok
exit 0
