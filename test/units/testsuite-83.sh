#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

: >/failed

systemd-analyze log-level debug

export SYSTEMD_LOG_LEVEL=debug

cleanup() {
    set +e
    systemctl stop mock-polkit.service
    systemctl stop test-bus-polkit.service
    userdel test83
}

trap cleanup EXIT

useradd -M -N -g nobody test83

systemctl start test-bus-polkit.service

runuser -u test83 busctl call io.systemd.test.TestBusPolkit /io/systemd/test/TestBusPolkit io.systemd.test.TestBusPolkit TestNoPolkit

systemctl start mock-polkit.service

runuser -u test83 busctl call io.systemd.test.TestBusPolkit /io/systemd/test/TestBusPolkit io.systemd.test.TestBusPolkit TestAllowed
runuser -u test83 busctl call io.systemd.test.TestBusPolkit /io/systemd/test/TestBusPolkit io.systemd.test.TestBusPolkit TestDenied
runuser -u test83 busctl call io.systemd.test.TestBusPolkit /io/systemd/test/TestBusPolkit io.systemd.test.TestBusPolkit TestInteractive
runuser -u test83 busctl call io.systemd.test.TestBusPolkit /io/systemd/test/TestBusPolkit io.systemd.test.TestBusPolkit TestUnknown

touch /testok
rm /failed

exit 0
