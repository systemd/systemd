#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

systemd-pty-forward --background 41 --title test echo foobar

# Test that signals are forwarded to the systemd-pty-forward child process.
cat >/tmp/child <<\EOF
#!/usr/bin/env bash
set -x

trap 'touch /tmp/int' INT

# We need to wait for the sleep process asynchronously in order to allow
# bash to process signals
sleep infinity &

# notify that the process is ready
touch /tmp/ready

PID=$!
while :; do
    wait || :
done
EOF

chmod +x /tmp/child

systemd-pty-forward /tmp/child &
PID=$!

timeout 5 bash -c "until test -e /tmp/ready; do sleep .5; done"

kill -INT "$PID"

timeout 5 bash -c "until test -e /tmp/int; do sleep .5; done"

kill "$PID"
