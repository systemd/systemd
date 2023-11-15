#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

DUMMY_SERVICE=/tmp/dummy-service.sh

cat >"$DUMMY_SERVICE" <<EOF
#!/usr/bin/env bash

state=2
function soft_reset() {
    echo "Handling reset request..."
    state=1
    echo "Passivated"
}
trap soft_reset SIGHUP

function full_stop() {
    echo "Handling stop request..."
    state=0
    echo "Stopped"
}
trap full_stop SIGTERM

# half seconds
lameduck=8
echo "Running main loop..."
while [ "\$state" -gt 0 -a "\$lameduck" -gt 0 ] ; do
    sleep .5
    if [ "\$state" -eq 1 ] ; then
       lameduck=\$((\$lameduck - 1))
    fi
done
echo "Exiting \$state:\$lameduck"
EOF

chmod u+x "$DUMMY_SERVICE"

cat >/run/systemd/system/testservice-85-foo#.service <<EOF
[Service]
ExecStart=$DUMMY_SERVICE
ExecStop=-/usr/bin/kill -SIGTERM \$MAINPID
ExecRestartPre=/usr/bin/kill -SIGHUP \$MAINPID
ExecRestartPre=/usr/bin/sleep 1
RuntimePassiveMaxSec=infinity
EOF

systemctl daemon-reload

### test rtemplate behavior
systemctl log-level debug

logger "MARK start"
systemctl start testservice-85-foo.service
# check one gen exists
active_inst1="$(systemctl show -P Following testservice-85-foo.service)"
[[ "$active_inst1" =~ testservice-85-foo#[^.]*.service ]]
systemctl is-active "$active_inst1"

logger "MARK restart"
systemctl restart testservice-85-foo.service
# check two gens exist
active_inst2="$(systemctl show -P Following testservice-85-foo.service)"
[[ "$active_inst1" != "$active_inst2" ]]
systemctl is-active "$active_inst1"
systemctl is-active "$active_inst2"

logger "MARK restart 2"
pid1_before="$(systemctl show -P MainPID "$active_inst1")"
systemctl restart testservice-85-foo.service
# check three gens exist
active_inst3="$(systemctl show -P Following testservice-85-foo.service)"
[[ "$active_inst3" != "$active_inst1" ]]
[[ "$active_inst3" != "$active_inst2" ]]
systemctl is-active "$active_inst1"
systemctl is-active "$active_inst2"
systemctl is-active "$active_inst3"
pid1_after="$(systemctl show -P MainPID "$active_inst1")"
[[ "$pid1_before" = "$pid1_after" ]]


sleep 5
# check one gen exists
! systemctl is-active "$active_inst1"
! systemctl is-active "$active_inst2"
systemctl is-active "$active_inst3"

logger "MARK stop"
systemctl stop testservice-85-foo.service
sleep 1
# check no gen exists
! systemctl is-active "$active_inst1"
! systemctl is-active "$active_inst2"
! systemctl is-active "$active_inst3"

systemctl log-level info
