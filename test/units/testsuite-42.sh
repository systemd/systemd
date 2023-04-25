#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux

systemd-analyze log-level debug

systemd-run --unit=simple1.service --wait -p StandardOutput=tty -p StandardError=tty -p Type=simple \
    -p ExecStopPost='/bin/touch /run/simple1' true
test -f /run/simple1

(! systemd-run --unit=simple2.service --wait -p StandardOutput=tty -p StandardError=tty -p Type=simple \
    -p ExecStopPost='/bin/touch /run/simple2' false)
test -f /run/simple2

systemd-run --unit=exec1.service --wait -p StandardOutput=tty -p StandardError=tty -p Type=exec \
    -p ExecStopPost='/bin/touch /run/exec1' sleep 1
test -f /run/exec1

(! systemd-run --unit=exec2.service --wait -p StandardOutput=tty -p StandardError=tty -p Type=exec \
   -p ExecStopPost='/bin/touch /run/exec2' sh -c 'sleep 1; false')
test -f /run/exec2

cat >/tmp/forking1.sh <<EOF
#!/usr/bin/env bash

set -eux

sleep 4 &
MAINPID=\$!
disown

systemd-notify MAINPID=\$MAINPID
EOF
chmod +x /tmp/forking1.sh

systemd-run --unit=forking1.service --wait -p StandardOutput=tty -p StandardError=tty -p Type=forking -p NotifyAccess=exec \
        -p ExecStopPost='/bin/touch /run/forking1' /tmp/forking1.sh
test -f /run/forking1

cat >/tmp/forking2.sh <<EOF
#!/usr/bin/env bash

set -eux

(sleep 4; exit 1) &
MAINPID=\$!
disown

systemd-notify MAINPID=\$MAINPID
EOF
chmod +x /tmp/forking2.sh

(! systemd-run --unit=forking2.service --wait -p StandardOutput=tty -p StandardError=tty -p Type=forking -p NotifyAccess=exec \
    -p ExecStopPost='/bin/touch /run/forking2' /tmp/forking2.sh)
test -f /run/forking2

systemd-run --unit=oneshot1.service --wait -p StandardOutput=tty -p StandardError=tty -p Type=oneshot \
    -p ExecStopPost='/bin/touch /run/oneshot1' true
test -f /run/oneshot1

(! systemd-run --unit=oneshot2.service --wait -p StandardOutput=tty -p StandardError=tty -p Type=oneshot \
    -p ExecStopPost='/bin/touch /run/oneshot2' false)
test -f /run/oneshot2

systemd-run --unit=dbus1.service --wait -p StandardOutput=tty -p StandardError=tty -p Type=dbus -p BusName=systemd.test.ExecStopPost \
    -p ExecStopPost='/bin/touch /run/dbus1' \
    busctl call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus RequestName su systemd.test.ExecStopPost 4 || :
test -f /run/dbus1

systemd-run --unit=dbus2.service --wait -p StandardOutput=tty -p StandardError=tty -p Type=dbus -p BusName=systemd.test.ExecStopPost \
     -p ExecStopPost='/bin/touch /run/dbus2' true
test -f /run/dbus2

# https://github.com/systemd/systemd/issues/19920
(! systemd-run --unit=dbus3.service --wait -p StandardOutput=tty -p StandardError=tty -p Type=dbus \
    -p ExecStopPost='/bin/touch /run/dbus3' true)

cat >/tmp/notify1.sh <<EOF
#!/usr/bin/env bash

set -eux

systemd-notify --ready
EOF
chmod +x /tmp/notify1.sh

systemd-run --unit=notify1.service --wait -p StandardOutput=tty -p StandardError=tty -p Type=notify \
    -p ExecStopPost='/bin/touch /run/notify1' /tmp/notify1.sh
test -f /run/notify1

(! systemd-run --unit=notify2.service --wait -p StandardOutput=tty -p StandardError=tty -p Type=notify \
    -p ExecStopPost='/bin/touch /run/notify2' true)
test -f /run/notify2

systemd-run --unit=idle1.service --wait -p StandardOutput=tty -p StandardError=tty -p Type=idle -p ExecStopPost='/bin/touch /run/idle1' true
test -f /run/idle1

(! systemd-run --unit=idle2.service --wait -p StandardOutput=tty -p StandardError=tty -p Type=idle \
     -p ExecStopPost='/bin/touch /run/idle2' false)
test -f /run/idle2

systemd-analyze log-level info

echo OK >/testok

exit 0
