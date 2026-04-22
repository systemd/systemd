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
"$REPORT" describe-metrics
"$REPORT" describe-metrics -j
"$REPORT" describe-metrics --no-legend
"$REPORT" list-sources
"$REPORT" list-sources -j
"$REPORT" list-sources --no-legend

"$REPORT" metrics io
"$REPORT" metrics io.systemd piff
"$REPORT" metrics piff
"$REPORT" describe-metrics io
"$REPORT" describe-metrics io.systemd piff
"$REPORT" describe-metrics piff

# test io.systemd.CGroup Metrics
systemctl start systemd-report-cgroup.socket
varlinkctl info /run/systemd/report/io.systemd.CGroup
varlinkctl list-methods /run/systemd/report/io.systemd.CGroup
varlinkctl --more call /run/systemd/report/io.systemd.CGroup io.systemd.Metrics.List {}
varlinkctl --more call /run/systemd/report/io.systemd.CGroup io.systemd.Metrics.Describe {}

# test io.systemd.PID1 Metrics
systemctl start systemd-report-pid1.socket
varlinkctl info /run/systemd/report/io.systemd.PID1
varlinkctl list-methods /run/systemd/report/io.systemd.PID1
varlinkctl --more call /run/systemd/report/io.systemd.PID1 io.systemd.Metrics.List {}
varlinkctl --more call /run/systemd/report/io.systemd.PID1 io.systemd.Metrics.Describe {}

# Confirm all four metric families are advertised by Describe and that
# every one produces a value via List. CpuTime is additionally split by
# mode (user, kernel) via the "fields" sub-object of each List reply.
PID1_DESCRIBE=$(varlinkctl --more call /run/systemd/report/io.systemd.PID1 io.systemd.Metrics.Describe {})
PID1_LIST=$(varlinkctl --more call /run/systemd/report/io.systemd.PID1 io.systemd.Metrics.List {})
for m in CpuTime FDCount MemoryUsage Tasks; do
    echo "$PID1_DESCRIBE" | grep >/dev/null "\"io.systemd.PID1.$m\""
    echo "$PID1_LIST"     | grep >/dev/null "\"io.systemd.PID1.$m\""
done
echo "$PID1_LIST" | grep >/dev/null '"mode"[[:space:]]*:[[:space:]]*"user"'
echo "$PID1_LIST" | grep >/dev/null '"mode"[[:space:]]*:[[:space:]]*"kernel"'

# test io.systemd.Network Metrics
varlinkctl info /run/systemd/report/io.systemd.Network
varlinkctl list-methods /run/systemd/report/io.systemd.Network
varlinkctl --more call /run/systemd/report/io.systemd.Network io.systemd.Metrics.List {}
varlinkctl --more call /run/systemd/report/io.systemd.Network io.systemd.Metrics.Describe {}

# Make sure the service for "system facts" is enabled
systemctl start systemd-report-basic.socket

# Test facts verbs
"$REPORT" facts
"$REPORT" facts -j
"$REPORT" facts --no-legend
"$REPORT" describe-facts
"$REPORT" describe-facts -j
"$REPORT" describe-facts --no-legend

# Test facts with match filters
"$REPORT" facts io
"$REPORT" facts io.systemd piff
"$REPORT" facts piff
"$REPORT" describe-facts io
"$REPORT" describe-facts io.systemd piff
"$REPORT" describe-facts piff

# Test facts via direct Varlink call on existing socket
varlinkctl --more call /run/systemd/report/io.systemd.Basic io.systemd.Facts.List {}
varlinkctl --more call /run/systemd/report/io.systemd.Basic io.systemd.Facts.Describe {}

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

"$REPORT" metrics --url=http://localhost:8089/
"$REPORT" facts --url=http://localhost:8089/

# Test HTTPS upload with generated TLS certificates
openssl req -x509 -newkey rsa:2048 -keyout "$CERTDIR/server.key" -out "$CERTDIR/server.crt" \
    -days 1 -nodes -subj "/CN=localhost" 2>/dev/null

systemd-run -p Type=notify --unit=fake-report-server-tls \
    "$FAKE_SERVER" --cert="$CERTDIR/server.crt" --key="$CERTDIR/server.key" --port=8090
systemctl status fake-report-server-tls

"$REPORT" metrics --url=https://localhost:8090/ --key=- --trust="$CERTDIR/server.crt"
"$REPORT" facts --url=https://localhost:8090/ --key=- --trust="$CERTDIR/server.crt" \
          --extra-header='Authorization: Bearer magic string'
