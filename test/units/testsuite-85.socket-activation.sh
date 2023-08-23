#!/usr/bin/env bash
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

TEST_SERVICE_BINARY=/usr/lib/systemd/tests/unit-tests/manual/test-service-rtemplate

cat >/run/systemd/system/testsuite-85-bar.socket <<EOF
[Socket]
ListenStream=/run/testsuite-85-bar.sock
EOF

cat >/run/systemd/system/testsuite-85-bar#.service <<EOF
[Service]
ExecStart=$TEST_SERVICE_BINARY
ExecRestartPre=/usr/bin/kill -SIGUSR1 \$MAINPID
ExecRestartPre=/usr/bin/sleep 1
EOF

systemctl daemon-reload

systemd-analyze log-level debug

# Start the test service socket
systemctl start testsuite-85-bar.socket

# Run 10 clients on the background
for i in {1..10}; do
    socat -t2 GOPEN:"/tmp/client-$i.log" UNIX-CONNECT:/run/testsuite-85-bar.sock &
done

trap "rm -rf /tmp/client*.log" EXIT

# Give clients some time to connect
sleep 1

# Here we test the actual "zero-dowtime restarts" concept. Previously started clients (on-background) should run
# undisturbed and continue to be handled by the first generation of the service.
systemctl restart testsuite-85-bar.service

# Connect one more client now after service is restarted
socat -t2 GOPEN:/tmp/client-11.log UNIX-CONNECT:/run/testsuite-85-bar.sock &

# Wait for all clients to finish
wait

# Verify that we got 50 (5 for each client started before restart of the service) lines
# with same generation id and 5 with different generation id for the last client started after restart
assert_eq $(cat /tmp/client-{1..10}.log | wc -l) 50
assert_eq $(sort -u /tmp/client-{1..10}.log | wc -l) 1
GEN1=$(head -n1 /tmp/client-1.log)

assert_eq $(grep -c "GENERATION_ID=" /tmp/client-11.log) 5
assert_eq $(grep -c "$GEN1" /tmp/client-11.log) 0

# Stop the test units
systemctl stop testsuite-85-bar.socket
systemctl stop testsuite-85-bar.service

systemd-analyze log-level info
