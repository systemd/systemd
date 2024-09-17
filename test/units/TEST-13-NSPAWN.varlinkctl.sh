#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016

set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

export PAGER=

at_exit() {
    machinectl status long-running >/dev/null && machinectl kill --signal=KILL long-running
    mountpoint -q /var/lib/machines && timeout 10 sh -c "until umount /var/lib/machines; do sleep .5; done"
}

trap at_exit EXIT

systemctl service-log-level systemd-machined debug
systemctl service-log-level systemd-importd debug

# Mount temporary directory over /var/lib/machines to not pollute the image
mkdir -p /var/lib/machines
mount --bind "$(mktemp --tmpdir=/var/tmp -d)" /var/lib/machines

# Create one "long running" container with some basic signal handling
create_dummy_container /var/lib/machines/long-running
cat >/var/lib/machines/long-running/sbin/init <<\EOF
#!/usr/bin/bash

PID=0

trap "touch /trap" TRAP
trap 'kill $PID' EXIT

# We need to wait for the sleep process asynchronously in order to allow
# bash to process signals
sleep infinity &

# notify that the process is ready
touch /ready

PID=$!
while :; do
    wait || :
done
EOF

machine_start() {
    machinectl status long-running >/dev/null && return 0 || true

    rm -f /var/lib/machines/long-running/ready
    # sometime `machinectl start` returns 1 and then do a success
    machinectl start long-running || machinectl start long-running
    # !!!! DO NOT REMOVE THIS TEST
    # The test makes sure that the long-running's init script has enough time to start and registered signal traps
    timeout 30 bash -c "until test -e /var/lib/machines/long-running/ready; do sleep .5; done"
}

machine_start

# test io.systemd.Machine.List
varlinkctl --more call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.List '{}' | grep 'long-running'
varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.List '{"name":"long-running"}'

# test io.systemd.Machine.Get
varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.Get '{"name":"long-running"}'

# test io.systemd.Machine.GetByPID
pid=$(varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.Get '{"name":"long-running"}' | jq .leader)
varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.Get '{"name":"long-running"}' >/tmp/expected
varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.GetByPID "{\"pid\":$pid}" >/tmp/got
diff -u /tmp/expected /tmp/got

# test io.systemd.Machine.Kill
# sending TRAP signal
rm -f /var/lib/machines/long-running/trap
varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.Kill '{"name":"long-running", "who": "leader", "signal": 5}'
timeout 30 bash -c "until test -e /var/lib/machines/long-running/trap; do sleep .5; done"

# sending KILL signal
varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.Kill '{"name":"long-running", "signal": 9}'
timeout 30 bash -c "while varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.Get '{\"name\":\"long-running\"}'; do sleep 0.5; done"

# test io.systemd.Machine.Terminate
machine_start
varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.Terminate '{"name":"long-running"}'
timeout 120 bash -c "while varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.Get '{\"name\":\"long-running\"}'; do sleep 0.5; done"
