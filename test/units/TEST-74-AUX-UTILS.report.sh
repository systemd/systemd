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

# test io.systemd.Network Metrics
varlinkctl info /run/systemd/report/io.systemd.Network
varlinkctl list-methods /run/systemd/report/io.systemd.Network
varlinkctl --more call /run/systemd/report/io.systemd.Network io.systemd.Metrics.List {}
varlinkctl --more call /run/systemd/report/io.systemd.Network io.systemd.Metrics.Describe {}

# Make sure the service for "system facts" is enabled
systemctl start systemd-report-basic.socket

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

"$REPORT" build-report io.systemd.Manager.UnitsTotal

"$REPORT" build-report io.systemd.Manager.UnitsTotal | jq .

"$REPORT" upload-report --url=http://localhost:8089/

# Test HTTPS upload with generated TLS certificates
openssl req -x509 -newkey rsa:2048 -keyout "$CERTDIR/server.key" -out "$CERTDIR/server.crt" \
    -days 1 -nodes -subj "/CN=localhost" 2>/dev/null

systemd-run -p Type=notify --unit=fake-report-server-tls \
    "$FAKE_SERVER" --cert="$CERTDIR/server.crt" --key="$CERTDIR/server.key" --port=8090
systemctl status fake-report-server-tls

"$REPORT" upload-report --url=https://localhost:8090/ --key=- --trust="$CERTDIR/server.crt" \
          --extra-header='Authorization: Bearer magic string'
