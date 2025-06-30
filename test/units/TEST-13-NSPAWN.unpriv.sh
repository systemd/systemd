#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

at_exit() {
    rm -rf /home/testuser/.local/state/machines/zurps ||:
    machinectl terminate zurps ||:
    rm -f /usr/share/polkit-1/rules.d/registermachinetest.rules
}

run0 -u testuser mkdir -p .local/state/machines

create_dummy_container /home/testuser/.local/state/machines/zurps
systemd-dissect --shift /home/testuser/.local/state/machines/zurps foreign

# Install a PK rule that allows 'testuser' user to register a machine even
# though they are not on an fg console, just for testing
cat >/usr/share/polkit-1/rules.d/registermachinetest.rules <<'EOF'
polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.machine1.register-machine" &&
        subject.user == "testuser") {
        return polkit.Result.YES;
    }
});
EOF

run0 -u testuser systemctl start --user systemd-nspawn@zurps.service

machinectl status zurps
machinectl status zurps | grep "UID:" | grep "$(id -u)"
machinectl status zurps | grep "Unit: user@" | grep "$(id -u)"
machinectl status zurps | grep "Subgroup: machine.slice/systemd-nspawn@zurps.service/supervisor"
machinectl terminate zurps

(! run0 -u testuser systemctl is-active --user systemd-nspawn@zurps.service)
