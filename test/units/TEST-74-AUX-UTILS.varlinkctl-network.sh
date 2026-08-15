#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# test io.systemd.Network
varlinkctl info /run/systemd/netif/io.systemd.Network
varlinkctl introspect /run/systemd/netif/io.systemd.Network io.systemd.Network
varlinkctl call /run/systemd/netif/io.systemd.Network io.systemd.Network.Describe '{}'
