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

# test io.systemd.Basic Metrics
systemctl start systemd-report-basic.socket
varlinkctl info /run/systemd/report/io.systemd.Basic
varlinkctl list-methods /run/systemd/report/io.systemd.Basic
varlinkctl --more call /run/systemd/report/io.systemd.Basic io.systemd.Metrics.List {}
varlinkctl --more call /run/systemd/report/io.systemd.Basic io.systemd.Metrics.Describe {}

id1="$(varlinkctl call --more /run/systemd/report/io.systemd.Basic io.systemd.Metrics.List {} | jq --seq -r 'select(.name == "io.systemd.Basic.OSRelease.ID") | .value')"
id2="$(. /etc/os-release; echo "$ID")"
[ "$id1" = "$id2" ]

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
