#!/usr/bin/env bash
set -ex

systemd-analyze log-level debug

# Multiple level process tree, parent process stays up
cat >/tmp/test59-any.sh <<EOF
#!/usr/bin/env bash
set -eux

# process tree: systemd -> sleep
sleep infinity &
disown

# process tree: systemd -> bash -> bash -> sleep
((sleep infinity); true) &

# process tree: systemd -> bash -> sleep
sleep infinity
EOF
chmod +x /tmp/test59-any.sh

# service should be stopped cleanly
(sleep 1; systemctl stop one) &
systemd-run --wait --unit=one -p Type=any /tmp/test59-any.sh

# service should exit uncleanly
(sleep 1; killall -9 sleep) &
! systemd-run --wait --unit=two -p Type=any /tmp/test59-any.sh


# Multiple level process tree, parent process exits quickly
cat >/tmp/test59-any-parentless.sh <<EOF
#!/usr/bin/env bash
set -eux

# process tree: systemd -> sleep
sleep infinity &

# process tree: systemd -> bash -> sleep
((sleep infinity); true) &
EOF
chmod +x /tmp/test59-any-parentless.sh

# service should be stopped cleanly
(sleep 1; systemctl stop three) &
systemd-run --wait --unit=three -p Type=any /tmp/test59-any-parentless.sh

# service should exit uncleanly
(sleep 1; killall -9 sleep) &
! systemd-run --wait --unit=four -p Type=any /tmp/test59-any-parentless.sh


# Multiple level process tree, parent process exits uncleanly but last process exits cleanly
cat >/tmp/test59-any-clean.sh <<EOF
#!/usr/bin/env bash
set -eux

# process tree: systemd -> bash -> sleep
(sleep 1; true) &

exit 255
EOF
chmod +x /tmp/test59-any-clean.sh

# service should exit cleanly and be garbage-collected
systemd-run --wait --unit=five -p Type=any /tmp/test59-any-clean.sh


# Multiple level process tree, parent process exits cleanly but last process exits uncleanly
cat >/tmp/test59-any-unclean.sh <<EOF
#!/usr/bin/env bash
set -eux

# process tree: systemd -> bash -> sleep
(sleep 1; exit 255) &
EOF
chmod +x /tmp/test59-any-unclean.sh

# service should exit uncleanly after 1 second
! systemd-run --wait --unit=six -p Type=any /tmp/test59-any-unclean.sh

systemd-analyze log-level info

echo OK > /testok

exit 0
