#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

systemd-analyze log-level debug

# Create a binary for which execve() will fail
touch /tmp/brokenbinary
chmod +x /tmp/brokenbinary

# These three commands should succeed.
systemd-run --unit=one -p Type=simple /bin/sleep infinity
systemd-run --unit=two -p Type=simple -p User=idontexist /bin/sleep infinity
systemd-run --unit=three -p Type=simple /tmp/brokenbinary

# And now, do the same with Type=exec, where the latter two should fail
systemd-run --unit=four -p Type=exec /bin/sleep infinity
(! systemd-run --unit=five -p Type=exec -p User=idontexist /bin/sleep infinity)
(! systemd-run --unit=six -p Type=exec /tmp/brokenbinary)

systemd-run --unit=seven -p KillSignal=SIGTERM -p RestartKillSignal=SIGINT -p Type=exec /bin/sleep infinity
# Both TERM and SIGINT happen to have the same number on all architectures
test "$(systemctl show --value -p KillSignal seven.service)" -eq 15
test "$(systemctl show --value -p RestartKillSignal seven.service)" -eq 2

systemctl restart seven.service
systemctl stop seven.service

# For issue #20933

# Should work normally
busctl call \
    org.freedesktop.systemd1 /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager StartTransientUnit \
    "ssa(sv)a(sa(sv))" test-20933-ok.service replace 1 \
      ExecStart "a(sasb)" 1 \
        /usr/bin/sleep 2 /usr/bin/sleep 1 true \
    0

# DBus call should fail but not crash systemd
(! busctl call \
    org.freedesktop.systemd1 /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager StartTransientUnit \
    "ssa(sv)a(sa(sv))" test-20933-bad.service replace 1 \
      ExecStart "a(sasb)" 1 \
        /usr/bin/sleep 0 true \
    0)

# Same but with the empty argv in the middle
(! busctl call \
    org.freedesktop.systemd1 /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager StartTransientUnit \
    "ssa(sv)a(sa(sv))" test-20933-bad-middle.service replace 1 \
      ExecStart "a(sasb)" 3 \
        /usr/bin/sleep 2 /usr/bin/sleep 1 true \
        /usr/bin/sleep 0                  true \
        /usr/bin/sleep 2 /usr/bin/sleep 1 true \
    0)

systemd-analyze log-level info

echo OK >/testok

exit 0
