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
    rm -rf /home/testuser/.local/state/machines/.tar-file* ||:
    rm -rf /home/testuser/.local/state/machines/zurps ||:
    rm -rf /home/testuser/.local/state/machines/nurps ||:
    rm -rf /home/testuser/.local/state/machines/kurps ||:
    rm -rf /home/testuser/.local/state/machines/wumms ||:
    rm -rf /home/testuser/.local/state/machines/wamms ||:
    rm -rf /home/testuser/.local/state/machines/inodetest ||:
    rm -rf /home/testuser/.local/state/machines/inodetest2 ||:
    rm -rf /home/testuser/.local/state/machines/mangletest ||:
    rm -rf /home/testuser/.local/state/machines/fdstore ||:
    machinectl terminate zurps ||:
    machinectl terminate exfiltrate ||:
    systemctl --user --machine testuser@ stop exfiltrate.service ||:
    systemctl --user --machine testuser@ stop systemd-nspawn@fdstore.service ||:
    rm -f /etc/polkit-1/rules.d/registermachinetest.rules
    machinectl terminate nurps ||:
    machinectl terminate kurps ||:
    machinectl terminate wumms ||:
    machinectl terminate wamms ||:
    machinectl terminate fdstore ||:
    rm -f /usr/share/polkit-1/rules.d/registermachinetest.rules
    rm -rf /var/tmp/mangletest
    rm -f /var/tmp/mangletest.tar.gz
    rm -f /shouldnotwork
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

run0 -u testuser \
    systemd-run --unit sleep.service --user sleep infinity
sleep_pid="$(run0 -u testuser systemctl show --user -P MainPID sleep.service)"
run0 -u testuser  \
    varlinkctl \
        call \
        /run/systemd/machine/io.systemd.Machine \
        io.systemd.Machine.Register \
        "{\"name\":\"shouldnotwork3\", \"class\":\"container\", \"leader\": $sleep_pid}"
(! run0 -u testuser \
    varlinkctl \
        call \
        /run/systemd/machine/io.systemd.Machine \
        io.systemd.Machine.Open \
        '{"name":"shouldnotwork3", "mode": "shell", "user":"root","path":"/usr/bin/bash","args":["bash","-c","''touch /shouldnotwork; sleep 20''"]}')
(! varlinkctl \
    call \
    /run/systemd/machine/io.systemd.Machine \
    io.systemd.Machine.Register \
    "{\"name\":\"shouldnotwork4\", \"class\":\"host\", \"leader\": $sleep_pid}")
(! machinectl list | grep shouldnotwork4)
(! run0 -u testuser  \
    varlinkctl \
        call \
        /run/systemd/machine/io.systemd.Machine \
        io.systemd.Machine.Register \
        "{\"name\":\"shouldnotwork5\", \"class\":\"host\", \"leader\": $sleep_pid}")
(! machinectl list | grep shouldnotwork5)
(! busctl call \
    org.freedesktop.machine1 \
    /org/freedesktop/machine1 \
    org.freedesktop.machine1.Manager \
    RegisterMachine \
    'sayssus' \
    shouldnotwork6 \
    0 \
    "" \
    host \
    0 \
    "")
(! machinectl list | grep shouldnotwork6)
(! run0 -u testuser \
    busctl call \
        org.freedesktop.machine1 \
        /org/freedesktop/machine1 \
        org.freedesktop.machine1.Manager \
        RegisterMachine \
        'sayssus' \
        shouldnotwork7 \
        0 \
        "" \
        host \
        0 \
        "")
(! machinectl list | grep shouldnotwork7)
systemctl --user --machine testuser@ stop sleep.service
test ! -f /shouldnotwork

echo FOO=bar >/tmp/foo
chmod 600 /tmp/foo
run0 -u testuser \
    systemd-run --unit exfiltrate.service --service-type notify --property NotifyAccess=all --user \
        unshare --map-root-user --user --mount \
            bash -c 'mount --bind /tmp/foo /usr/lib/os-release; systemd-notify --ready; exec sleep infinity'
exfiltrate_pid="$(systemctl --machine testuser@.host show --user -P MainPID exfiltrate.service)"
run0 -u testuser \
    varlinkctl \
        call \
        /run/systemd/machine/io.systemd.Machine \
        io.systemd.Machine.Register \
        "{\"name\":\"exfiltrate\", \"class\":\"container\", \"leader\": $exfiltrate_pid}"
exfiltrate_output="$(run0 -u testuser \
    varlinkctl \
        call \
        /run/systemd/machine/io.systemd.Machine io.systemd.Machine.List \
        "{\"name\":\"exfiltrate\",\"acquireMetadata\":\"graceful\"}" 2>&1)" || true
(! echo "$exfiltrate_output" | grep '"name".*"exfiltrate"' >/dev/null)
(! echo "$exfiltrate_output" | grep "FOO=bar" >/dev/null)
systemctl --user --machine testuser@ stop exfiltrate.service

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

mkdir /home/testuser/.local/state/machines/inodetest
echo hallo >/home/testuser/.local/state/machines/inodetest/testfile

# Make the file sparse, set an xattr, set an ACL, set a chattr flag, and make it hardlink
ln /home/testuser/.local/state/machines/inodetest/testfile /home/testuser/.local/state/machines/inodetest/testfile.hard
truncate -s 1M /home/testuser/.local/state/machines/inodetest/testfile
setfattr -n "user.piff" -v "paff" /home/testuser/.local/state/machines/inodetest/testfile
setfacl -m g:foreign-47:rwx /home/testuser/.local/state/machines/inodetest/testfile
chattr +A /home/testuser/.local/state/machines/inodetest/testfile
chown foreign-0:foreign-0 /home/testuser/.local/state/machines/inodetest/testfile.hard /home/testuser/.local/state/machines/inodetest
ls -al /home/testuser/.local/state/machines/inodetest

# Verify UID squashing
echo gaga >/home/testuser/.local/state/machines/inodetest/squashtest
chown 1000:1000 /home/testuser/.local/state/machines/inodetest/squashtest

# Ensure hardlinked symlinks work
ln -s sometarget /home/testuser/.local/state/machines/inodetest/testfile.sym
ln /home/testuser/.local/state/machines/inodetest/testfile.sym /home/testuser/.local/state/machines/inodetest/testfile.symhard
chown -h foreign-0:foreign-0 /home/testuser/.local/state/machines/inodetest/testfile.symhard

run0 --pipe -u testuser importctl -m --user export-tar inodetest |
    run0 --pipe -u testuser importctl -m --user import-tar - inodetest2

ls -al /home/testuser/.local/state/machines/inodetest2

cmp /home/testuser/.local/state/machines/inodetest/testfile /home/testuser/.local/state/machines/inodetest2/testfile.hard
cmp <(stat -c"%s %b %B" /home/testuser/.local/state/machines/inodetest/testfile) <(stat -c"%s %b %B" /home/testuser/.local/state/machines/inodetest2/testfile)
cmp <(stat -c"%i" /home/testuser/.local/state/machines/inodetest2/testfile) <(stat -c"%i" /home/testuser/.local/state/machines/inodetest2/testfile.hard)
getfattr -d /home/testuser/.local/state/machines/inodetest/testfile
getfattr -d /home/testuser/.local/state/machines/inodetest2/testfile
getfacl /home/testuser/.local/state/machines/inodetest/testfile
getfacl /home/testuser/.local/state/machines/inodetest2/testfile
lsattr /home/testuser/.local/state/machines/inodetest/testfile
lsattr /home/testuser/.local/state/machines/inodetest2/testfile
cmp <(getfattr -d /home/testuser/.local/state/machines/inodetest/testfile | grep -v ^#) <(getfattr -d /home/testuser/.local/state/machines/inodetest2/testfile | grep -v ^#)
cmp <(getfacl /home/testuser/.local/state/machines/inodetest/testfile | grep -v ^#) <(getfacl /home/testuser/.local/state/machines/inodetest2/testfile | grep -v ^#)
cmp <(lsattr /home/testuser/.local/state/machines/inodetest/testfile | cut -d " " -f1) <(lsattr /home/testuser/.local/state/machines/inodetest2/testfile | cut -d " " -f1)

# verify that squashing outside of 64K works
test "$(stat -c'%U:%G' /home/testuser/.local/state/machines/inodetest2/squashtest)" = "foreign-65534:foreign-65534"

# Verify that the hardlinked symlink is restored as such
cmp <(stat -c"%i" /home/testuser/.local/state/machines/inodetest2/testfile.sym) <(stat -c"%i" /home/testuser/.local/state/machines/inodetest2/testfile.symhard)
test "$(readlink /home/testuser/.local/state/machines/inodetest2/testfile.symhard)" = "sometarget"

# chown to foreign UID range, so that removal works
chown foreign-4711:foreign-4711 /home/testuser/.local/state/machines/inodetest/squashtest

run0 -u testuser machinectl --user remove inodetest
run0 -u testuser machinectl --user remove inodetest2

# Test tree mangling (i.e. moving the root dir one level up on extract)
mkdir -p /var/tmp/mangletest/mangletest-0.1/usr/lib
echo "ID=brumm" >/var/tmp/mangletest/mangletest-0.1/usr/lib/os-release
tar -C /var/tmp/mangletest/ -cvzf /var/tmp/mangletest.tar.gz mangletest-0.1
run0 --pipe -u testuser importctl -m --user import-tar /var/tmp/mangletest.tar.gz
cmp /var/tmp/mangletest/mangletest-0.1/usr/lib/os-release /home/testuser/.local/state/machines/mangletest/usr/lib/os-release

# Verify the fd-store preservation chain works end-to-end across:
#   payload (inside container) -> systemd-nspawn (user manager) -> user manager
#   -> system PID 1 (user@<UID>.service fd store)
# Then restart the nspawn service and verify the inner payload actually
# receives the preserved fds back via LISTEN_FDS, with their original content.
create_dummy_container /home/testuser/.local/state/machines/fdstore
# The container init execs the helper directly so the FDSTORE notification is
# sent from PID 1 (nspawn rejects notify messages from anyone but the inner
# payload's init). The helper itself execs sleep on success to keep the
# container alive, and on failure it exits non-zero making the systemd-nspawn
# service fail.
cat >/home/testuser/.local/state/machines/fdstore/sbin/init <<'EOF'
#!/usr/bin/env bash
set -e
if [[ "${LISTEN_FDS:-0}" -gt 0 ]]; then
    exec /usr/bin/test-fdstore check
else
    exec /usr/bin/test-fdstore store
fi
EOF
chmod +x /home/testuser/.local/state/machines/fdstore/sbin/init
systemd-dissect --shift /home/testuser/.local/state/machines/fdstore foreign

run0 -u testuser mkdir -p .config/systemd/nspawn/
run0 -u testuser -i "cat >.config/systemd/nspawn/fdstore.nspawn <<EOF
[Exec]
KillSignal=SIGKILL
EOF"

run0 -u testuser mkdir -p ".config/systemd/user/systemd-nspawn@fdstore.service.d/"
run0 -u testuser -i "cat >.config/systemd/user/systemd-nspawn@fdstore.service.d/fdstore.conf <<EOF
[Service]
FileDescriptorStoreMax=8
FileDescriptorStorePreserve=yes
EOF"
run0 -u testuser systemctl --user daemon-reload

run0 -u testuser systemctl start --user systemd-nspawn@fdstore.service
timeout 30s bash -c \
    "until [[ \"\$(run0 -u testuser systemctl --user show -P NFileDescriptorStore systemd-nspawn@fdstore.service)\" -ge 2 ]]; do sleep 0.5; done"

# 1) Payload -> nspawn (user-side systemd-nspawn@fdstore.service fd store)
n_nspawn_fds=$(run0 -u testuser systemctl --user show -P NFileDescriptorStore systemd-nspawn@fdstore.service)
test "${n_nspawn_fds}" -ge 2

# 2) nspawn -> user manager -> system PID 1 (user@<UID>.service fd store)
TESTUSER_UID=$(id -u testuser)
timeout 30s bash -c \
    "until [[ \"\$(systemctl show -P NFileDescriptorStore user@${TESTUSER_UID}.service)\" -ge 2 ]]; do sleep 0.5; done"
n_user_at_fds=$(systemctl show -P NFileDescriptorStore "user@${TESTUSER_UID}.service")
test "${n_user_at_fds}" -ge 2

# 3) Stop the nspawn service: payload is gone but FileDescriptorStorePreserve=yes
# must keep the fds in the user-side fdstore (and propagated copy in PID 1).
run0 -u testuser systemctl --user stop systemd-nspawn@fdstore.service
n_nspawn_fds=$(run0 -u testuser systemctl --user show -P NFileDescriptorStore systemd-nspawn@fdstore.service)
test "${n_nspawn_fds}" -ge 2

# 4) Restart the service: nspawn must receive the preserved fds via LISTEN_FDS
# and forward them into the inner payload, which verifies the content matches.
run0 -u testuser systemctl start --user systemd-nspawn@fdstore.service
run0 -u testuser systemctl is-active --user systemd-nspawn@fdstore.service

# 5) Stop the nspawn service and the user session
run0 -u testuser systemctl --user stop systemd-nspawn@fdstore.service
n_nspawn_fds=$(run0 -u testuser systemctl --user show -P NFileDescriptorStore systemd-nspawn@fdstore.service)
test "${n_nspawn_fds}" -ge 2
systemctl stop "user@${TESTUSER_UID}.service"
n_user_at_fds=$(systemctl show -P NFileDescriptorStore "user@${TESTUSER_UID}.service")
test "${n_user_at_fds}" -ge 2

# 6) Restart the user session and container payload
systemctl start "user@${TESTUSER_UID}.service"
timeout 30s bash -c \
    "until systemctl is-active 'user@${TESTUSER_UID}.service' >/dev/null; do sleep 0.5; done"
run0 -u testuser systemctl --user start systemd-nspawn@fdstore.service
run0 -u testuser systemctl is-active --user systemd-nspawn@fdstore.service

run0 -u testuser systemctl --user stop systemd-nspawn@fdstore.service
machinectl terminate fdstore 2>/dev/null || true

loginctl disable-linger testuser
