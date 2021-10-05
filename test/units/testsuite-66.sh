#!/usr/bin/env bash
set -eux
set -o pipefail

systemd-analyze log-level debug

# Should work normally
busctl call \
  org.freedesktop.systemd1 /org/freedesktop/systemd1 \
  org.freedesktop.systemd1.Manager StartTransientUnit \
  "ssa(sv)a(sa(sv))" test-ok.service replace 1 \
    ExecStart "a(sasb)" 1 \
      /usr/bin/sleep 2 /usr/bin/sleep infinity true \
  0

# DBus call should fail but not crash systemd
busctl call \
  org.freedesktop.systemd1 /org/freedesktop/systemd1 \
  org.freedesktop.systemd1.Manager StartTransientUnit \
  "ssa(sv)a(sa(sv))" test-bad.service replace 1 \
    ExecStart "a(sasb)" 1 \
      /usr/bin/sleep 0 true \
  0 && { echo 'unexpected success'; exit 1; }

# Same but with the empty argv in the middle
busctl call \
  org.freedesktop.systemd1 /org/freedesktop/systemd1 \
  org.freedesktop.systemd1.Manager StartTransientUnit \
  "ssa(sv)a(sa(sv))" test-bad-middle.service replace 1 \
    ExecStart "a(sasb)" 3 \
      /usr/bin/sleep 2 /usr/bin/sleep 1 true \
      /usr/bin/sleep 0                  true \
      /usr/bin/sleep 2 /usr/bin/sleep 1 true \
  0 && { echo 'unexpected success'; exit 1; }

systemd-analyze log-level info

echo OK >/testok

exit 0
