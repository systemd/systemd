#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# test io.systemd.Metrics
varlinkctl info /run/systemd/report/io.systemd.Manager

varlinkctl list-methods /run/systemd/report/io.systemd.Manager
varlinkctl list-methods -j /run/systemd/report/io.systemd.Manager io.systemd.Metrics | jq .

varlinkctl introspect /run/systemd/report/io.systemd.Manager
varlinkctl introspect -j /run/systemd/report/io.systemd.Manager io.systemd.Metrics | jq .

varlinkctl --more call /run/systemd/report/io.systemd.Manager io.systemd.Metrics.List '{}'
varlinkctl --more call /run/systemd/report/io.systemd.Manager io.systemd.Metrics.Describe '{}'
