#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Unset $PAGER so we don't have to use --no-pager everywhere
export PAGER=

systemd-report --help
systemd-report help
systemd-report --version
systemd-report --json=help

systemd-report metrics
systemd-report metrics -j
systemd-report metrics --no-legend
systemd-report describe-metrics
systemd-report describe-metrics -j
systemd-report describe-metrics --no-legend
systemd-report list-sources
systemd-report list-sources -j
systemd-report list-sources --no-legend

systemd-report metrics io
systemd-report metrics io.systemd piff
systemd-report metrics piff
systemd-report describe-metrics io
systemd-report describe-metrics io.systemd piff
systemd-report describe-metrics piff

# test io.systemd.Network Metrics
varlinkctl info /run/systemd/report/io.systemd.Network
varlinkctl list-methods /run/systemd/report/io.systemd.Network
varlinkctl --more call /run/systemd/report/io.systemd.Network io.systemd.Metrics.List {}
varlinkctl --more call /run/systemd/report/io.systemd.Network io.systemd.Metrics.Describe {}
