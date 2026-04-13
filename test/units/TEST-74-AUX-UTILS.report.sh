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
