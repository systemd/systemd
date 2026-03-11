#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Units with excessive numbers of fields in LogExtraFields=.
# Issue: https://github.com/systemd/systemd/issues/40916

UNIT=test-07-pid1-issue-40916.service

cleanup() {
    rm -f /run/systemd/system/"$UNIT"
    systemctl daemon-reload
}

trap cleanup EXIT

cat >/run/systemd/system/"$UNIT" <<EOF
[Service]
ExecStart=true
EOF

for i in {1..2000}; do
    echo "LogExtraFields=FIELD_$i=$i"
done >>/run/systemd/system/"$UNIT"

systemctl start --wait "$UNIT"

systemctl show -p LogExtraFields "$UNIT" | grep FIELD_1000
(! systemctl show -p LogExtraFields "$UNIT" | grep FIELD_1500)

# Now try setting the properties dynamically
(! systemd-run --wait -u test-07-pid1-issue-40916-1.service -pLogExtraFields=FD{1..2000}=1 true)
systemd-run --wait -u test-07-pid1-issue-40916-1.service -pLogExtraFields=FD{1..1000}=1 true
