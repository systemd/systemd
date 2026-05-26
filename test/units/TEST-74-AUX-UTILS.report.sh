#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Unset $PAGER so we don't have to use --no-pager everywhere
export PAGER=

REPORT=/usr/lib/systemd/systemd-report

"$REPORT" --help
"$REPORT" help
"$REPORT" --version
"$REPORT" --json=help

"$REPORT" metrics
"$REPORT" metrics -j
"$REPORT" metrics --no-legend
"$REPORT" describe
"$REPORT" describe -j
"$REPORT" describe --no-legend
"$REPORT" list-sources
"$REPORT" list-sources -j
"$REPORT" list-sources --no-legend

"$REPORT" metrics io
"$REPORT" metrics io.systemd piff
"$REPORT" metrics piff
"$REPORT" describe io
"$REPORT" describe io.systemd piff
"$REPORT" describe piff

# test io.systemd.CGroup Metrics
systemctl start systemd-report-cgroup.socket
varlinkctl info /run/systemd/report/io.systemd.CGroup
varlinkctl list-methods /run/systemd/report/io.systemd.CGroup
varlinkctl --more call /run/systemd/report/io.systemd.CGroup io.systemd.Metrics.List {}
varlinkctl --more call /run/systemd/report/io.systemd.CGroup io.systemd.Metrics.Describe {}

# CpuUsage emits one row per (cgroup, type) where type is total, user, or system.
# Confirm all three are present.
cgroup_metrics=$(varlinkctl --more --json=short call /run/systemd/report/io.systemd.CGroup io.systemd.Metrics.List {})
echo "$cgroup_metrics" | grep '"name":"io.systemd.CGroup.CpuUsage"' | grep '"type":"total"' >/dev/null
echo "$cgroup_metrics" | grep '"name":"io.systemd.CGroup.CpuUsage"' | grep '"type":"user"' >/dev/null
echo "$cgroup_metrics" | grep '"name":"io.systemd.CGroup.CpuUsage"' | grep '"type":"system"' >/dev/null

# test io.systemd.Network Metrics
varlinkctl info /run/systemd/report/io.systemd.Network
varlinkctl list-methods /run/systemd/report/io.systemd.Network
varlinkctl --more call /run/systemd/report/io.systemd.Network io.systemd.Metrics.List {}
varlinkctl --more call /run/systemd/report/io.systemd.Network io.systemd.Metrics.Describe {}

varlinkctl --more --json=short call /run/systemd/report/io.systemd.Network io.systemd.Metrics.Describe {} | grep '"name":"io.systemd.Network.Address"' >/dev/null
# we do not send "lo"
net_metrics="$(varlinkctl call --more --json=short /run/systemd/report/io.systemd.Network io.systemd.Metrics.List {})"
(! echo "$net_metrics" | grep '"name":"io.systemd.Network.Address"' | grep '"object":"lo"' >/dev/null)
# add a scratch address and check that it shows up.
ip address add 192.0.2.1/32 dev lo
timeout 30 bash -c 'until varlinkctl call --more --json=short /run/systemd/report/io.systemd.Network io.systemd.Metrics.List {} | grep -F "192.0.2.1/32" >/dev/null; do sleep .5; done'
net_metrics="$(varlinkctl call --more --json=short /run/systemd/report/io.systemd.Network io.systemd.Metrics.List {})"
echo "$net_metrics" | grep '"name":"io.systemd.Network.Address"' | grep '"object":"lo"' | grep '"value":"192.0.2.1/32"' | grep '"family":"ipv4"' >/dev/null
ip address del 192.0.2.1/32 dev lo

# test io.systemd.Basic Metrics
# ensure the socket is running, as some distros don't enable it by default
systemctl start systemd-report-basic.socket
varlinkctl info /run/systemd/report/io.systemd.Basic
varlinkctl list-methods /run/systemd/report/io.systemd.Basic
varlinkctl --more call /run/systemd/report/io.systemd.Basic io.systemd.Metrics.List {}
varlinkctl --more call /run/systemd/report/io.systemd.Basic io.systemd.Metrics.Describe {}

id1="$(varlinkctl call --more /run/systemd/report/io.systemd.Basic io.systemd.Metrics.List {} | jq --seq -r 'select(.name == "io.systemd.Basic.OSRelease.ID") | .value')"
id2="$(. /etc/os-release; echo "$ID")"
[ "$id1" = "$id2" ]

# io.systemd.Manager.Version should be non-empty and match what `systemctl --version` reports
metrics_version="$(varlinkctl call --more /run/systemd/report/io.systemd.Manager io.systemd.Metrics.List {} | jq --seq -r 'select(.name == "io.systemd.Manager.Version") | .value')"
[ -n "$metrics_version" ]
systemctl --version | grep -F "($metrics_version)" >/dev/null

# Boot timeline timestamps. The kernel CLOCK_MONOTONIC is 0 by definition, so only its realtime is
# reported; userspace reports both realtime and monotonic. We don't check FinishTimestamp here:
# the test runs as a service, so manager_check_finished() typically hasn't fired yet and the
# timestamp is unset (the metric is then suppressed). Likewise KernelTimestamp is cleared when
# systemd runs inside a container (see main.c), so the metric is suppressed there too.
manager_metrics="$(varlinkctl call --more /run/systemd/report/io.systemd.Manager io.systemd.Metrics.List {})"
metric_value() { echo "$manager_metrics" | jq --seq -r "select(.name == \"io.systemd.Manager.$1\") | .value | tostring"; }
if ! systemd-detect-virt --quiet --container; then
    [ "$(metric_value KernelTimestamp.Realtime)" -gt 0 ]
fi
[ "$(metric_value UserspaceTimestamp.Realtime)" -gt 0 ]
[ "$(metric_value UserspaceTimestamp.Monotonic)" -gt 0 ]

# test io.systemd.Basic.MachineInfo.* metrics, sourced from /etc/machine-info
if [ -e /etc/machine-info ]; then
    MACHINE_INFO_BACKUP="$(mktemp)"
    cp /etc/machine-info "$MACHINE_INFO_BACKUP"
    MACHINE_INFO_EXISTED=1
else
    MACHINE_INFO_EXISTED=0
fi

restore_machine_info() {
    set +e
    if [ "$MACHINE_INFO_EXISTED" = 1 ]; then
        cp "$MACHINE_INFO_BACKUP" /etc/machine-info
        rm -f "$MACHINE_INFO_BACKUP"
    else
        rm -f /etc/machine-info
    fi
    set -e
}
trap restore_machine_info EXIT

cat >/etc/machine-info <<EOF
PRETTY_HOSTNAME="Test Machine"
DEPLOYMENT=test
LOCATION="Test Lab, Rack 3"
TAGS=foo:bar:baz
EOF

# The metric source re-reads /etc/machine-info on every call, so no service restart is needed.
machine_info_metrics="$(varlinkctl call --more /run/systemd/report/io.systemd.Basic io.systemd.Metrics.List {})"
machine_info_value() { echo "$machine_info_metrics" | jq --seq -r "select(.name == \"$1\") | .value"; }

[ "$(machine_info_value io.systemd.Basic.MachineInfo.PRETTY_HOSTNAME)" = "Test Machine" ]
[ "$(machine_info_value io.systemd.Basic.MachineInfo.DEPLOYMENT)" = "test" ]
[ "$(machine_info_value io.systemd.Basic.MachineInfo.LOCATION)" = "Test Lab, Rack 3" ]
[ "$(machine_info_value io.systemd.Basic.MachineInfo.TAGS)" = "foo:bar:baz" ]

restore_machine_info
trap - EXIT

# Test HTTP upload (plain http)
FAKE_SERVER=/usr/lib/systemd/tests/integration-tests/TEST-74-AUX-UTILS/TEST-74-AUX-UTILS.units/fake-report-server.py
CERTDIR=$(mktemp -d)

at_exit() {
    set +e
    systemctl stop fake-report-server fake-report-server-tls
    rm -rf "$CERTDIR"
}
trap at_exit EXIT

systemd-run -p Type=notify --unit=fake-report-server "$FAKE_SERVER"
systemctl status fake-report-server

"$REPORT" generate io.systemd.Manager.UnitsTotal

"$REPORT" generate io.systemd.Manager.UnitsTotal | jq .

"$REPORT" upload --url=http://localhost:8089/

# Test HTTPS upload with generated TLS certificates
openssl req -x509 -newkey rsa:2048 -keyout "$CERTDIR/server.key" -out "$CERTDIR/server.crt" \
    -days 1 -nodes -subj "/CN=localhost" 2>/dev/null

systemd-run -p Type=notify --unit=fake-report-server-tls \
    "$FAKE_SERVER" --cert="$CERTDIR/server.crt" --key="$CERTDIR/server.key" --port=8090
systemctl status fake-report-server-tls

"$REPORT" upload --url=https://localhost:8090/ --key=- --trust="$CERTDIR/server.crt" \
          --extra-header='Authorization: Bearer magic string'
