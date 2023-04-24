#!/usr/bin/env bash
set -eux

systemd-analyze log-level debug

# Multiple level process tree, parent process stays up
cat >/tmp/test56-exit-cgroup.sh <<EOF
#!/usr/bin/env bash
set -eux

# process tree: systemd -> sleep
sleep infinity &
disown

# process tree: systemd -> bash -> bash -> sleep
((sleep infinity); true) &

systemd-notify --ready

# Run the stop/kill command
\$1 &

# process tree: systemd -> bash -> sleep
sleep infinity
EOF
chmod +x /tmp/test56-exit-cgroup.sh

# service should be stopped cleanly
systemd-run --wait --unit=one -p Type=notify -p ExitType=cgroup \
    /tmp/test56-exit-cgroup.sh 'systemctl stop one'

# same thing with a truthy exec condition
systemd-run --wait --unit=two -p Type=notify -p ExitType=cgroup \
    -p ExecCondition=true \
    /tmp/test56-exit-cgroup.sh 'systemctl stop two'

# false exec condition: systemd-run should exit immediately with status code: 1
(! systemd-run --wait --unit=three -p Type=notify -p ExitType=cgroup \
    -p ExecCondition=false \
    /tmp/test56-exit-cgroup.sh)

# service should exit uncleanly (main process exits with SIGKILL)
(! systemd-run --wait --unit=four -p Type=notify -p ExitType=cgroup \
    /tmp/test56-exit-cgroup.sh 'systemctl kill --signal 9 four')


# Multiple level process tree, parent process exits quickly
cat >/tmp/test56-exit-cgroup-parentless.sh <<EOF
#!/usr/bin/env bash
set -eux

# process tree: systemd -> sleep
sleep infinity &

# process tree: systemd -> bash -> sleep
((sleep infinity); true) &

systemd-notify --ready

# Run the stop/kill command after this bash process exits
(sleep 1; \$1) &
EOF
chmod +x /tmp/test56-exit-cgroup-parentless.sh

# service should be stopped cleanly
systemd-run --wait --unit=five -p Type=notify -p ExitType=cgroup \
    /tmp/test56-exit-cgroup-parentless.sh 'systemctl stop five'

# service should still exit cleanly despite SIGKILL (the main process already exited cleanly)
systemd-run --wait --unit=six -p Type=notify -p ExitType=cgroup \
    /tmp/test56-exit-cgroup-parentless.sh 'systemctl kill --signal 9 six'


systemd-analyze log-level info

echo OK >/testok

exit 0
