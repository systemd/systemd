#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

if ! can_do_rootless_nspawn; then
    echo "Skipping unpriv nspawn test"
    exit 0
fi

at_exit() {
    rm -rf /home/testuser/.local/state/machines/zurps ||:
    rm -rf /home/testuser/.local/state/machines/nurps ||:
    rm -rf /home/testuser/.local/state/machines/kurps ||:
    rm -rf /home/testuser/.local/state/machines/wumms ||:
    rm -rf /home/testuser/.local/state/machines/wamms ||:
    machinectl terminate zurps ||:
    rm -f /etc/polkit-1/rules.d/registermachinetest.rules
    machinectl terminate nurps ||:
    machinectl terminate kurps ||:
    machinectl terminate wumms ||:
    machinectl terminate wamms ||:
    rm -f /usr/share/polkit-1/rules.d/registermachinetest.rules
}

trap at_exit EXIT

run0 -u testuser mkdir -p .local/state/machines

create_dummy_container /home/testuser/.local/state/machines/zurps
cat >/home/testuser/.local/state/machines/zurps/sbin/init <<EOF
#!/usr/bin/env bash
echo "I am living in a container"
exec sleep infinity
EOF
chmod +x /home/testuser/.local/state/machines/zurps/sbin/init
systemd-dissect --shift /home/testuser/.local/state/machines/zurps foreign

# Install a PK rule that allows 'testuser' user to register a machine even
# though they are not on an fg console, just for testing
mkdir -p /etc/polkit-1/rules.d
cat >/etc/polkit-1/rules.d/registermachinetest.rules <<'EOF'
polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.machine1.register-machine" &&
        subject.user == "testuser") {
        return polkit.Result.YES;
    }
});
EOF

loginctl enable-linger testuser

run0 -u testuser mkdir -p .config/systemd/nspawn/
run0 -u testuser -i "echo -e \"[Exec]\nKillSignal=SIGKILL\n\" > .config/systemd/nspawn/zurps.nspawn"
run0 -u testuser systemctl start --user systemd-nspawn@zurps.service

machinectl status zurps
machinectl status zurps | grep "UID:" | grep "$(id -u testuser)"
machinectl status zurps | grep "Unit: user@" | grep "$(id -u testuser)"
machinectl status zurps | grep "Subgroup: machine.slice/systemd-nspawn@zurps.service/payload"
machinectl terminate zurps

(! run0 -u testuser systemctl is-active --user systemd-nspawn@zurps.service)

(! run0 -u testuser \
    busctl call \
        org.freedesktop.machine1 \
        /org/freedesktop/machine1 \
        org.freedesktop.machine1.Manager \
        RegisterMachine \
        'sayssus' \
        shouldnotwork1 \
        16 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 \
        "" \
        container \
        "$(systemctl show -p MainPID --value systemd-logind.service)" \
        "$PWD")

run0 -u testuser \
    busctl call \
        org.freedesktop.machine1 \
        /org/freedesktop/machine1 \
        org.freedesktop.machine1.Manager \
        RegisterMachine \
        'sayssus' \
        shouldnotwork2 \
        16 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 \
        "" \
        container \
        "$(systemctl show -p MainPID --value user@4711.service)" \
        "$PWD"
(! run0 -u testuser machinectl shell shouldnotwork2 /usr/bin/id -u)
(! run0 -u testuser machinectl shell root@shouldnotwork2 /usr/bin/id -u)
(! run0 -u testuser machinectl shell 0@shouldnotwork2 /usr/bin/id -u)
(! run0 -u testuser machinectl shell testuser@shouldnotwork2 /usr/bin/id -u)

run0 -u testuser mkdir /var/tmp/image-tar
run0 -u testuser importctl --user export-tar zurps /var/tmp/image-tar/kurps.tar.gz -m
run0 -u testuser importctl --user import-tar /var/tmp/image-tar/kurps.tar.gz -m

run0 -u testuser -i "echo -e \"[Exec]\nKillSignal=SIGKILL\n\" > .config/systemd/nspawn/kurps.nspawn"
run0 -u testuser systemctl start --user systemd-nspawn@kurps.service
machinectl terminate kurps

run0 -u testuser -D /var/tmp/image-tar/ bash -c 'sha256sum kurps.tar.gz > SHA256SUMS'
run0 -u testuser importctl --user pull-tar file:///var/tmp/image-tar/kurps.tar.gz nurps --verify=checksum -m

run0 -u testuser -i "echo -e \"[Exec]\nKillSignal=SIGKILL\n\" > .config/systemd/nspawn/nurps.nspawn"
run0 -u testuser systemctl start --user systemd-nspawn@nurps.service
machinectl terminate nurps

run0 -u testuser rm -r /var/tmp/image-tar

run0 -u testuser importctl --user list-images
run0 -u testuser machinectl --user list-images

assert_in 'zurps' "$(run0 --pipe -u testuser machinectl --user list-images)"
assert_in 'nurps' "$(run0 --pipe -u testuser machinectl --user list-images)"
assert_in 'kurps' "$(run0 --pipe -u testuser machinectl --user list-images)"

run0 -u testuser machinectl --user image-status zurps
run0 -u testuser machinectl --user image-status nurps
run0 -u testuser machinectl --user image-status kurps

run0 -u testuser machinectl --user show-image zurps
run0 -u testuser machinectl --user show-image nurps
run0 -u testuser machinectl --user show-image kurps

run0 -u testuser machinectl --user clone zurps wumms

assert_in 'wumms' "$(run0 -u testuser machinectl --user list-images)"
run0 -u testuser machinectl --user image-status wumms
run0 -u testuser machinectl --user show-image wumms

run0 -u testuser machinectl --user rename wumms wamms
assert_not_in 'wumms' "$(run0 -u testuser machinectl --user list-images)"
assert_in 'wamms' "$(run0 -u testuser machinectl --user list-images)"
run0 -u testuser machinectl --user image-status wamms
run0 -u testuser machinectl --user show-image wamms

run0 -u testuser -i "echo -e \"[Exec]\nKillSignal=SIGKILL\n\" > .config/systemd/nspawn/wamms.nspawn"
run0 -u testuser systemctl start --user systemd-nspawn@wamms.service

run0 -u testuser systemctl stop --user systemd-nspawn@zurps.service
run0 -u testuser systemctl stop --user systemd-nspawn@nurps.service
run0 -u testuser systemctl stop --user systemd-nspawn@kurps.service
run0 -u testuser systemctl stop --user systemd-nspawn@wamms.service

run0 -u testuser machinectl --user remove zurps
run0 -u testuser machinectl --user remove kurps
run0 -u testuser machinectl --user remove nurps
run0 -u testuser machinectl --user remove wamms

assert_not_in 'zurps' "$(run0 --pipe -u testuser machinectl --user list-images)"
assert_not_in 'nurps' "$(run0 --pipe -u testuser machinectl --user list-images)"
assert_not_in 'kurps' "$(run0 --pipe -u testuser machinectl --user list-images)"

loginctl disable-linger testuser
