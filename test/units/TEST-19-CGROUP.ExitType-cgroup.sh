#!/usr/bin/env bash
set -eux

# Test ExitType=cgroup

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

if [[ "$(get_cgroup_hierarchy)" != unified ]]; then
    echo "Skipping $0 as we're not running with the unified cgroup hierarchy"
    exit 0
fi

systemd-analyze log-level debug

# Multiple level process tree, parent process stays up
cat >/tmp/test19-exit-cgroup.sh <<EOF
#!/usr/bin/env bash
set -eux

# process tree: systemd -> sleep
sleep infinity &
disown

# process tree: systemd -> bash -> bash -> sleep
((sleep infinity); true) &

systemd-notify --ready

# Run the stop/kill command, but sleep a bit to make the sleep infinity
# below actually started before stopping/killing the service.
(sleep 1; \$1) &

# process tree: systemd -> bash -> sleep
sleep infinity
EOF
chmod +x /tmp/test19-exit-cgroup.sh

# service should be stopped cleanly
systemd-run --wait \
           --unit=one \
           --property="Type=notify" \
           --property="ExitType=cgroup" \
           /tmp/test19-exit-cgroup.sh 'systemctl stop one'

# same thing with a truthy exec condition
systemd-run --wait \
            --unit=two \
            --property="Type=notify" \
            --property="ExitType=cgroup" \
            --property="ExecCondition=true" \
            /tmp/test19-exit-cgroup.sh 'systemctl stop two'

# false exec condition: systemd-run should exit immediately with status code: 1
(! systemd-run --wait \
               --unit=three \
               --property="Type=notify" \
               --property="ExitType=cgroup" \
               --property="ExecCondition=false" \
               /tmp/test19-exit-cgroup.sh)

# service should exit uncleanly (main process exits with SIGKILL)
(! systemd-run --wait \
               --unit=four \
               --property="Type=notify" \
               --property="ExitType=cgroup" \
               /tmp/test19-exit-cgroup.sh 'systemctl kill --signal 9 four')


# Multiple level process tree, parent process exits quickly
cat >/tmp/test19-exit-cgroup-parentless.sh <<EOF
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
chmod +x /tmp/test19-exit-cgroup-parentless.sh

# service should be stopped cleanly
systemd-run --wait \
            --unit=five \
            --property="Type=notify" \
            --property="ExitType=cgroup" \
            /tmp/test19-exit-cgroup-parentless.sh 'systemctl stop five'

# service should still exit cleanly despite SIGKILL (the main process already exited cleanly)
systemd-run --wait \
            --unit=six \
            --property="Type=notify" \
            --property="ExitType=cgroup" \
            /tmp/test19-exit-cgroup-parentless.sh 'systemctl kill --signal 9 six'


systemd-analyze log-level info
