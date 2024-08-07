#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux

# first test is to make sure that /var/log/journal is not created
# by starting a new journal namespace if the journald config has
# Storage=auto
cat << EOF > /etc/systemd/journald@foobar.conf
[Journal]
Storage=auto
EOF

# for the above to work, we need to use a service drop-in to override
# the default LogsDirectory, otherwise Storage=auto will not work.
mkdir -p /etc/systemd/system/systemd-journald@foobar.service.d
cat << EOF > /etc/systemd/system/systemd-journald@foobar.service.d/00-test.conf
[Service]
LogsDirectory=
EOF

# reload systemd to detect the new drop-in
systemctl daemon-reload

# ensure /var/log/journal does not exist
rm -rf /var/log/journal

systemd-run --wait -p LogNamespace=foobar echo "hello world"
if [[ -d /var/log/journal ]]; then
    echo "/var/log/journal was created with Storage=auto" >/failed
    exit 1
fi

# now the runtime journal should exist, and when we create the
# persistent journal path /var/log/journal, the runtime journal
# should be flushed and moved out of /run
# expect /var/log/journal/%m.foobar
mkdir -p /var/log/journal
MACHINE_ID=$(cat /etc/machine-id)

# allow a few seconds for the flush to occur due to machine speeds
WAS_FLUSHED=false
# shellcheck disable=SC2034,SC2015
for i in {1..5}; do [ -d "/var/log/journal/$MACHINE_ID.foobar" ] && WAS_FLUSHED=true && break || sleep 1; done
if ! $WAS_FLUSHED; then
    echo "/var/log/journal/$MACHINE_ID.foobar did not get created" >/failed
    exit 1
fi

# after the flush of the runtime journal it should have been cleaned up
if [[ -d "/run/log/journal/$MACHINE_ID.foobar" ]]; then
    echo "/run/log/journal/$MACHINE_ID.foobar was not flushed" >/failed
    exit 1
fi

echo OK >/testok
exit 0
