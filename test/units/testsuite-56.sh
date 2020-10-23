#!/usr/bin/env bash
set -ex
set -o pipefail

systemd-analyze log-level debug
systemd-analyze log-target console

# Loose checks to ensure the environment has the necessary features for systemd-oomd
[[ "$( awk '/SwapTotal/ { print $2 }' /proc/meminfo )" != "0" ]] || echo "no swap" >> /skipped
[[ -e /proc/pressure ]] || echo "no PSI" >> /skipped
cgroup_type=$(stat -fc %T /sys/fs/cgroup/)
if [[ "$cgroup_type" != *"cgroup2"* ]] && [[ "$cgroup_type" != *"0x63677270"* ]]; then
    echo "no cgroup2" >> /skipped
fi
[[ -e /skipped ]] && exit 0 || true

cat > /etc/systemd/system/testworkload.slice <<EOF
[Slice]
CPUAccounting=true
MemoryAccounting=true
IOAccounting=true
TasksAccounting=true
ManagedOOMMemoryPressure=kill
ManagedOOMMemoryPressureLimitPercent=50%
EOF

# Create a lot of memory pressure by setting memory.high to a very small value
cat > /etc/systemd/system/testbloat.service <<EOF
[Service]
MemoryHigh=2M
Slice=testworkload.slice
ExecStart=/usr/lib/systemd/tests/testdata/units/testsuite-56-slowgrowth.sh
EOF

# This generates no memory pressure
cat > /etc/systemd/system/testchill.service <<EOF
[Service]
MemoryHigh=2M
Slice=testworkload.slice
ExecStart=sleep infinity
EOF

systemctl daemon-reload

systemctl start testbloat.service
systemctl start testchill.service

# Verify systemd-oomd is monitoring the expected units
oomctl | grep "/testworkload.slice"
oomctl | grep "50%"

# systemd-oomd watches for elevated pressure for 30 seconds before acting.
# It can take time to build up pressure so either wait 5 minutes or for the service to fail.
timeout=$(date -ud "5 minutes" +%s)
while [[ $(date -u +%s) -le $timeout ]]; do
    if ! systemctl status testbloat.service; then
        break
    fi
    sleep 15
done

# testbloat should be killed and testchill should be fine
if systemctl status testbloat.service; then exit 42; fi
if ! systemctl status testchill.service; then exit 24; fi

systemd-analyze log-level info

echo OK > /testok

exit 0
