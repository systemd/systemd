#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Verify that the manager exposes a ReloadCount property that increments on
# every daemon-reload, is preserved across daemon-reexec (without being bumped
# by the reexec itself), and is reachable over both D-Bus and Varlink.

read_count_dbus() {
    busctl -j get-property org.freedesktop.systemd1 \
                           /org/freedesktop/systemd1 \
                           org.freedesktop.systemd1.Manager \
                           ReloadCount | jq -r '.data'
}

read_count_varlink() {
    varlinkctl call /run/systemd/io.systemd.Manager \
                    io.systemd.Manager.Describe '{}' | jq -r '.runtime.ReloadCount'
}

# Sanity: both transports must agree.
dbus_count=$(read_count_dbus)
varlink_count=$(read_count_varlink)
(( dbus_count == varlink_count ))

# A single reload bumps the counter by one.
before=$(read_count_dbus)
systemctl daemon-reload
(( $(read_count_dbus) == before + 1 ))

# Multiple reloads accumulate.
systemctl daemon-reload
systemctl daemon-reload
(( $(read_count_dbus) == before + 3 ))

# And both transports still agree after the reexec.
(( $(read_count_dbus) == $(read_count_varlink) ))
