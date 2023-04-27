#!/usr/bin/env bash
set -eux
set -o pipefail

: >/failed

systemd-analyze log-level debug

cat >/run/systemd/system/testsuite-99-restart-mode.socket <<EOF
[Socket]
ListenStream=/run/testsuite-99-restart-mode.sock
EOF

cat >/run/systemd/system/testsuite-99-restart-mode.service <<"EOF"
[Unit]
Description=RestarMode test service

[Service]
ExecStart=/usr/local/bin/service.py

RestartMode=keep
ExecRestart=/bin/bash -c '/bin/kill -USR1 $MAINPID && /bin/sleep 1'
EOF

systemctl daemon-reload

# Start the test service socket
systemctl start testsuite-99-restart-mode.socket

# Run 10 clients on the background
for i in {1..10}; do
    nc -U /run/testsuite-99-restart-mode.sock > "/tmp/client-$i.log" &
done

# Give clients some time to connect
sleep 1

# Here we test the actual "zero-dowtime restarts" concept. Previously started clients (on-background) should run
# undisturbed and continue to be handled by the first generation of the service.
systemctl restart testsuite-99-restart-mode.service

# Connect one more client now after service is restarted
nc -U /run/testsuite-99-restart-mode.sock > /tmp/client-11.log &

# Wait for all clients to finish
wait

# Verify that we got 50 (5 for each client started before restart of the service) lines
# with generation id 1 and 5 with generation id 2 for the last client started after restart
for i in {1..10}; do
    [ "$(grep -c "GENERATION_ID=1" "/tmp/client-$i.log")" = "5" ]
done
[ "$(grep -c "GENERATION_ID=2" "/tmp/client-11.log")" = "5" ]

# Check that Generation=property is exported over D-Bus
systemctl --no-pager show --property=Generation testsuite-99-restart-mode.service | grep -q 'Generation=2'

# Make sure ControlGroup= property points to the latest generation
systemctl --no-pager show --property=ControlGroup testsuite-99-restart-mode.service | grep -q 'ControlGroup=/system.slice/testsuite-99-restart-mode.service/2'

# Check that cgroup attributes set for the service are configured propertly (correctly exported and actually configured in cgroup fs)
systemctl set-property testsuite-99-restart-mode.service CPUWeight=200
systemctl show --property CPUWeight testsuite-99-restart-mode.service | grep -q 'CPUWeight=200'
grep -q 200 /sys/fs/cgroup/system.slice/testsuite-99-restart-mode.service/cpu.weight

# Check that service generation cgroups are listed in systemctl output
systemctl --no-pager status testsuite-99-restart-mode.service | grep -q 'CGroup: /system.slice/testsuite-99-restart-mode.service/1'
systemctl --no-pager status testsuite-99-restart-mode.service | grep -q 'CGroup: /system.slice/testsuite-99-restart-mode.service/2'

# Stop the test units
systemctl stop testsuite-99-restart-mode.socket
systemctl stop testsuite-99-restart-mode.service

systemd-analyze log-level info

echo OK >/testok
rm /failed

exit 0
