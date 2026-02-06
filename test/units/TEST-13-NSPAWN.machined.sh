#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

export PAGER=

at_exit() {
    set +e

    machinectl status long-running &>/dev/null && machinectl kill --signal=KILL long-running
    mountpoint -q /var/lib/machines && timeout 30 bash -c "until umount /var/lib/machines; do sleep .5; done"
    [[ -n "${NSPAWN_FRAGMENT:-}" ]] && rm -f "/etc/systemd/nspawn/$NSPAWN_FRAGMENT" "/var/lib/machines/$NSPAWN_FRAGMENT"
    rm -f /run/systemd/nspawn/*.nspawn
}

trap at_exit EXIT

# per request in https://github.com/systemd/systemd/pull/35117
systemctl edit --runtime --stdin 'systemd-nspawn@.service' --drop-in=debug.conf <<EOF
[Service]
Environment=SYSTEMD_LOG_LEVEL=debug
EOF

# Mount temporary directory over /var/lib/machines to not pollute the image
mkdir -p /var/lib/machines
mount --bind "$(mktemp --tmpdir=/var/tmp -d)" /var/lib/machines

# Create a couple of containers we can refer to in tests
for i in {0..4}; do
    create_dummy_container "/var/lib/machines/container$i"
    machinectl start "container$i"
done
# Create one "long running" container with some basic signal handling
create_dummy_container /var/lib/machines/long-running
cat >/var/lib/machines/long-running/sbin/init <<\EOF
#!/usr/bin/env bash

set -x

PID=0

trap 'touch /terminate; kill 0' RTMIN+3
trap 'touch /poweroff' RTMIN+4
trap 'touch /reboot' INT
trap 'touch /trap' TRAP
trap 'exit 0' TERM
trap 'kill $PID' EXIT

# We need to wait for the sleep process asynchronously in order to allow
# bash to process signals
sleep infinity &

# notify that the process is ready
touch /ready

PID=$!
while :; do
    wait || :
done
EOF

long_running_machine_start() {
    # shellcheck disable=SC2015
    machinectl status long-running &>/dev/null && return 0 || true

    # Ensure the service stopped.
    systemctl stop systemd-nspawn@long-running.service 2>/dev/null || :

    rm -f /var/lib/machines/long-running/ready
    machinectl start long-running
    # !!!! DO NOT REMOVE THIS TEST
    # The test makes sure that the long-running's init script has enough time to start and registered signal traps
    timeout 30 bash -c "until test -e /var/lib/machines/long-running/ready; do sleep .5; done"
}

long_running_machine_start

machinectl
machinectl --no-pager --help
machinectl --version
machinectl list
machinectl list --no-legend --no-ask-password

machinectl status long-running long-running long-running
machinectl status --full long-running
machinectl status --quiet --lines=1 long-running
machinectl status --lines=0 --max-addresses=0 long-running
machinectl status --machine=testuser@.host long-running
machinectl status --output=help long-running
while read -r output; do
    machinectl status --output="$output" long-running
done < <(machinectl --output=help)

machinectl show
machinectl show --all
machinectl show --all --machine=root@
machinectl show --all --machine=testuser@
[[ "$(machinectl show --property=PoolPath --value)" == "/var/lib/machines" ]]
machinectl show long-running
machinectl show long-running long-running long-running --all
[[ "$(machinectl show --property=RootDirectory --value long-running)" == "/var/lib/machines/long-running" ]]

machinectl enable long-running
test -L /etc/systemd/system/machines.target.wants/systemd-nspawn@long-running.service
machinectl enable long-running long-running long-running container1
machinectl disable long-running
test ! -L /etc/systemd/system/machines.target.wants/systemd-nspawn@long-running.service
machinectl disable long-running long-running long-running container1

[[ "$(TERM=dumb machinectl shell testuser@ /usr/bin/bash -c 'echo -ne $FOO')" == "" ]]
[[ "$(TERM=dumb machinectl shell --setenv=FOO=bar testuser@ /usr/bin/bash -c 'echo -ne $FOO')" == "bar" ]]

[[ "$(machinectl show --property=State --value long-running)" == "running" ]]
# Equivalent to machinectl kill --signal=SIGRTMIN+4 --kill-whom=leader
rm -f /var/lib/machines/long-running/poweroff
machinectl poweroff long-running
timeout 30 bash -c "until test -e /var/lib/machines/long-running/poweroff; do sleep .5; done"
# Equivalent to machinectl kill --signal=SIGINT --kill-whom=leader
rm -f /var/lib/machines/long-running/reboot
machinectl reboot long-running
timeout 30 bash -c "until test -e /var/lib/machines/long-running/reboot; do sleep .5; done"
# Test for 'machinectl terminate'
rm -f /var/lib/machines/long-running/terminate
machinectl terminate long-running
timeout 30 bash -c "until test -e /var/lib/machines/long-running/terminate; do sleep .5; done"
timeout 30 bash -c "while machinectl status long-running &>/dev/null; do sleep .5; done"
# Restart container
long_running_machine_start
# Test for 'machinectl kill'
rm -f /var/lib/machines/long-running/trap
machinectl kill --signal=SIGTRAP --kill-whom=leader long-running
timeout 30 bash -c "until test -e /var/lib/machines/long-running/trap; do sleep .5; done"
# Multiple machines at once
machinectl poweroff long-running long-running long-running
machinectl reboot long-running long-running long-running
machinectl kill --signal=SIGTRAP --kill-whom=leader long-running long-running long-running
# All used signals should've been caught by a handler
[[ "$(machinectl show --property=State --value long-running)" == "running" ]]

cp /etc/machine-id /tmp/foo
machinectl copy-to long-running /tmp/foo /root/foo
test -f /var/lib/machines/long-running/root/foo
machinectl copy-from long-running /root/foo /tmp/bar
diff /tmp/foo /tmp/bar
rm -f /tmp/{foo,bar}

# machinectl bind is covered by testcase_check_machinectl_bind() in nspawn tests

machinectl list-images
machinectl list-images --no-legend
machinectl image-status
machinectl image-status container1
machinectl image-status container1 container1 container{0..4}
machinectl show-image
machinectl show-image container1
machinectl show-image container1 container1 container{0..4}

machinectl clone container1 clone1
machinectl show-image clone1
machinectl rename clone1 clone2
(! machinectl show-image clone1)
machinectl show-image clone2
# `machinectl read-only` uses chattr (ioctl(FS_IOC_SETFLAGS)) when the container is backed by a directory,
# and this operation might not be implemented on certain filesystems (i.e. tmpfs on older kernels), so check
# if we have chattr support before running following tests
if lsattr -d /var/lib/machines >/dev/null; then
    [[ "$(machinectl show-image --property=ReadOnly --value clone2)" == no ]]
    machinectl read-only clone2 yes
    [[ "$(machinectl show-image --property=ReadOnly --value clone2)" == yes ]]
    machinectl read-only clone2 no
    [[ "$(machinectl show-image --property=ReadOnly --value clone2)" == no ]]
fi
machinectl remove clone2
for i in {0..4}; do
    machinectl clone container1 "clone$i"
done
machinectl remove clone{0..4}
for i in {0..4}; do
    machinectl clone container1 ".hidden$i"
done
machinectl list-images --all
test -d /var/lib/machines/.hidden1
machinectl clean
test ! -d /var/lib/machines/.hidden1

# Prepare a simple raw container
mkdir -p /tmp/mnt
truncate -s 256M /var/tmp/container.raw
mkfs.ext4 /var/tmp/container.raw
mount -o loop /var/tmp/container.raw /tmp/mnt
cp -r /var/lib/machines/container1/* /tmp/mnt
umount /tmp/mnt
# Try to import it, run it, export it, and re-import it
machinectl import-raw /var/tmp/container.raw container-raw
[[ "$(machinectl show-image --property=Type --value container-raw)" == "raw" ]]
machinectl start container-raw
machinectl export-raw container-raw /var/tmp/container-export.raw
machinectl import-raw /var/tmp/container-export.raw container-raw-reimport
[[ "$(machinectl show-image --property=Type --value container-raw-reimport)" == "raw" ]]
rm -f /var/tmp/container{,-export}.raw

# Prepare a simple tar.gz container
tar -pczf /var/tmp/container.tar.gz -C /var/lib/machines/container1 .
# Try to import it, run it, export it, and re-import it
machinectl import-tar /var/tmp/container.tar.gz container-tar
[[ "$(machinectl show-image --property=Type --value container-tar)" =~ directory|subvolume ]]
machinectl start container-tar
machinectl export-tar container-tar /var/tmp/container-export.tar.gz
machinectl import-tar /var/tmp/container-export.tar.gz container-tar-reimport
[[ "$(machinectl show-image --property=Type --value container-tar-reimport)" =~ directory|subvolume ]]
rm -f /var/tmp/container{,-export}.tar.gz

# Try to import a container directory & run it
cp -r /var/lib/machines/container1 /var/tmp/container.dir
machinectl import-fs /var/tmp/container.dir container-dir
[[ "$(machinectl show-image --property=Type --value container-dir)" =~ directory|subvolume ]]
machinectl start container-dir
rm -fr /var/tmp/container.dir

timeout 30 bash -c "until machinectl clean --all; do sleep .5; done"

NSPAWN_FRAGMENT="machinectl-test-$RANDOM.nspawn"
cat >"/var/lib/machines/$NSPAWN_FRAGMENT" <<EOF
[Exec]
Boot=true
EOF
machinectl cat "$NSPAWN_FRAGMENT"
EDITOR=true script -qec "machinectl edit $NSPAWN_FRAGMENT" /dev/null
test -f "/etc/systemd/nspawn/$NSPAWN_FRAGMENT"
diff "/var/lib/machines/$NSPAWN_FRAGMENT" "/etc/systemd/nspawn/$NSPAWN_FRAGMENT"

cat >/tmp/fragment.nspawn <<EOF
[Exec]
Boot=false
EOF
machinectl cat /tmp/fragment.nspawn
EDITOR="cp /tmp/fragment.nspawn" script -qec "machinectl edit $NSPAWN_FRAGMENT" /dev/null
diff /tmp/fragment.nspawn "/etc/systemd/nspawn/$NSPAWN_FRAGMENT"

for opt in format lines machine max-addresses output setenv verify; do
    (! machinectl status "--$opt=" long-running)
    (! machinectl status "--$opt=-1" long-running)
    (! machinectl status "--$opt=''" long-running)
done
(! machinectl show "")
(! machinectl enable)
(! machinectl enable "")
(! machinectl disable)
(! machinectl disable "")
(! machinectl read-only container1 "")
(! machinectl read-only container1 foo)
(! machinectl read-only container1 -- -1)

####################
# varlinkctl tests #
####################

long_running_machine_start

varlinkctl introspect /run/systemd/machine/io.systemd.Machine io.systemd.Machine
varlinkctl introspect /run/systemd/machine/io.systemd.Machine io.systemd.MachineImage
varlinkctl introspect /run/systemd/machine/io.systemd.MachineImage io.systemd.Machine
varlinkctl introspect /run/systemd/machine/io.systemd.MachineImage io.systemd.MachineImage

# test io.systemd.Machine.List
varlinkctl --more call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.List '{}' | grep 'long-running'
varlinkctl --more call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.List '{}' | grep '.host'
varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.List '{"name":"long-running"}'

pid=$(varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.List '{"name":"long-running"}' | jq '.leader')
varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.List '{"name":"long-running"}' >/tmp/expected
varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.List "{\"pid\":$pid}" | diff /tmp/expected -
varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.List "{\"name\":\"long-running\", \"pid\":$pid}" | diff /tmp/expected -
(! varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.List "{\"name\":\"non-existent\", \"pid\":$pid}")
(! varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.List '{"name":""}')
(! varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.List '{"name":"ah@??.hmm"}')

# test io.systemd.Machine.Kill
# sending TRAP signal
rm -f /var/lib/machines/long-running/trap
varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.Kill '{"name":"long-running", "whom": "leader", "signal": 5}'
timeout 120 bash -c "until test -e /var/lib/machines/long-running/trap; do sleep .5; done"

# sending KILL signal
varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.Kill '{"name":"long-running", "signal": 9}'
timeout 30 bash -c "while varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.List '{\"name\":\"long-running\"}'; do sleep 0.5; done"

# test io.systemd.Machine.Terminate
long_running_machine_start
rm -f /var/lib/machines/long-running/terminate
varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.Terminate '{"name":"long-running"}'
timeout 30 bash -c "until test -e /var/lib/machines/long-running/terminate; do sleep .5; done"
timeout 30 bash -c "while varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.List '{\"name\":\"long-running\"}'; do sleep 0.5; done"

# test io.systemd.Machine.Register
varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.Register '{"name": "registered-container", "class": "container"}'
timeout 30 bash -c "until varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.List '{\"name\":\"registered-container\"}'; do sleep 0.5; done"

# test io.systemd.Machine.Unregister
varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.Unregister '{"name": "registered-container"}'
timeout 30 bash -c "while varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.List '{\"name\":\"registered-container\"}'; do sleep 0.5; done"

# test io.systemd.Machine.List with sshAddress and sshPrivateKeyPath fields
varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.Register '{"name": "registered-container", "class": "container", "sshAddress": "localhost", "sshPrivateKeyPath": "/non-existent"}'
timeout 30 bash -c "until varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.List '{\"name\":\"registered-container\"}'; do sleep 0.5; done"
varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.List '{"name":"registered-container"}' | jq '.sshAddress' | grep 'localhost' >/dev/null
varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.List '{"name":"registered-container"}' | jq '.sshPrivateKeyPath' | grep 'non-existent' >/dev/null
varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.Unregister '{"name": "registered-container"}'

# test io.systemd.Machine.List with addresses, OSRelease, and UIDShift fields
create_dummy_container "/var/lib/machines/container-without-os-release"
cat >>/var/lib/machines/container-without-os-release/sbin/init <<\EOF
#!/usr/bin/env bash

set -x

ip link add hoge type dummy
ip link set hoge up
ip address add 192.0.2.1/24 dev hoge

PID=0

trap 'kill 0' RTMIN+3
trap 'exit 0' TERM
trap 'kill $PID' EXIT

# We need to wait for the sleep process asynchronously in order to allow
# bash to process signals
sleep infinity &

# notify that the process is ready
touch /ready

PID=$!
while :; do
    wait || :
done
EOF
machinectl start "container-without-os-release"
timeout 30 bash -c "until test -e /var/lib/machines/container-without-os-release/ready; do sleep .5; done"
rm -f /var/lib/machines/container-without-os-release/etc/os-release /var/lib/machines/container-without-os-release/usr/lib/os-release
(! varlinkctl --more call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.List '{"name": "container-without-os-release", "acquireMetadata": "yes"}')
output=$(varlinkctl --more call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.List '{"name": "container-without-os-release", "acquireMetadata": "graceful"}')
assert_eq "$(echo "$output" | jq --seq .name | tr -d \\036)" '"container-without-os-release"'
assert_eq "$(echo "$output" | jq --seq .class | tr -d \\036)" '"container"'
assert_eq "$(echo "$output" | jq --seq .service | tr -d \\036)" '"systemd-nspawn"'
assert_eq "$(echo "$output" | jq --seq .rootDirectory | tr -d \\036)" '"/var/lib/machines/container-without-os-release"'
assert_eq "$(echo "$output" | jq --seq .unit | tr -d \\036)" '"systemd-nspawn@container-without-os-release.service"'
assert_eq "$(echo "$output" | jq --seq .addresses[0].family | tr -d \\036)" '2'
assert_eq "$(echo "$output" | jq --seq .addresses[0].address[0] | tr -d \\036)" '192'
assert_eq "$(echo "$output" | jq --seq .addresses[0].address[1] | tr -d \\036)" '0'
assert_eq "$(echo "$output" | jq --seq .addresses[0].address[2] | tr -d \\036)" '2'
assert_eq "$(echo "$output" | jq --seq .addresses[0].address[3] | tr -d \\036)" '1'
# test for listing multiple machines.
long_running_machine_start
varlinkctl --more call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.List '{}'
varlinkctl --more call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.List '{"acquireMetadata": "no"}'
varlinkctl --more call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.List '{"acquireMetadata": "graceful"}'
# check if machined does not try to send anything after error message
journalctl --sync
TS="$(date '+%H:%M:%S')"
(! varlinkctl --more call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.List '{"acquireMetadata": "yes"}')
journalctl --sync
(! journalctl -u systemd-machined.service --since="$TS" --grep 'Connection busy')
machinectl terminate container-without-os-release

(ip addr show lo | grep 192.168.1.100 >/dev/null) || ip address add 192.168.1.100/24 dev lo
(! varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.List '{"name": ".host"}' | grep 'addresses')
varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.List '{"name": ".host", "acquireMetadata": "yes"}' | grep 'addresses'
(! varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.List '{"name": ".host"}' | grep 'OSRelease')
varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.List '{"name": ".host", "acquireMetadata": "yes"}' | grep 'OSRelease'
(! varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.List '{"name": ".host"}' | grep 'acquireUIDShift')
varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.List '{"name": ".host", "acquireMetadata": "yes"}' | grep 'UIDShift'

# test io.systemd.Machine.Open

# Reducing log level here is to work-around check in post.sh. Read https://github.com/systemd/systemd/pull/34867 for more details
systemctl service-log-level systemd-machined info
(! varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.Open '{"name": ".host"}')
(! varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.Open '{"name": ".host", "mode": ""}')
(! varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.Open '{"name": ".host", "mode": null}')
(! varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.Open '{"name": ".host", "mode": "foo"}')
systemctl service-log-level systemd-machined debug

varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.Open '{"name": ".host", "mode": "tty"}'
varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.Open '{"name": ".host", "mode": "login"}'
varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.Open '{"name": ".host", "mode": "shell"}'

rm -f /tmp/none-existent-file

# We need to make sure the acquired pty fd stays open if we invoke a command
# server side, to not generate early SIGHUP. Hence, let's just invoke "sleep
# infinity" client side, once we acquired the fd (passing it to it), and kill
# it once we verified everything worked.
PID=$(systemd-notify --fork -- varlinkctl --exec call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.Open '{"name": ".host", "mode": "shell", "user": "root", "path": "/usr/bin/bash", "args": ["bash", "-c", "echo $FOO >/tmp/none-existent-file"], "environment": ["FOO=BAR"]}' -- sleep infinity)
timeout 30 bash -c "until test -e /tmp/none-existent-file; do sleep .5; done"
grep -q "BAR" /tmp/none-existent-file
kill "$PID"

# Test varlinkctl's --exec fd passing logic properly
assert_eq "$(varlinkctl --exec call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.Open '{"name": ".host", "mode": "shell", "user": "root", "path": "/usr/bin/bash", "args": ["bash", "-c", "echo $((7 + 8))"], "environment": ["TERM=dumb"]}' -- bash -c 'read -r -N 2 x <&3 ; echo "$x"')" 15

# test io.systemd.Machine.MapFrom
varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.MapFrom '{"name": "long-running", "uid":0, "gid": 0}'
container_uid=$(varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.MapFrom '{"name": "long-running", "uid":0}' | jq '.uid')
container_gid=$(varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.MapFrom '{"name": "long-running", "gid":0}' | jq '.gid')
# test io.systemd.Machine.MapTo
varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.MapTo "{\"uid\": $container_uid, \"gid\": $container_gid}" | grep "long-running"
(! varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.MapTo '{"uid": 0}')
(! varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.MapTo '{"gid": 0}')

# io.systemd.Machine.BindMount is covered by testcase_check_machinectl_bind() in nspawn tests

# test io.systemd.Machine.CopyTo
rm -f /tmp/foo /var/lib/machines/long-running/root/foo
cp /etc/machine-id /tmp/foo
varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.CopyTo '{"name": "long-running", "source": "/tmp/foo", "destination": "/root/foo"}'
diff /tmp/foo /var/lib/machines/long-running/root/foo
(! varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.CopyTo '{"name": "long-running", "source": "/tmp/foo", "destination": "/root/foo"}') # FileExists
varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.CopyTo '{"name": "long-running", "source": "/tmp/foo", "destination": "/root/foo", "replace": true}'

echo "sample-test-output" >/tmp/foo
varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.CopyTo '{"name": "long-running", "source": "/tmp/foo", "destination": "/root/foo", "replace": true}'
diff /tmp/foo /var/lib/machines/long-running/root/foo
rm -f /tmp/foo /var/lib/machines/long-running/root/foo

# test io.systemd.Machine.CopyFrom
cp /etc/machine-id /var/lib/machines/long-running/foo
varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.CopyFrom '{"name": "long-running", "source": "/foo"}'
diff /var/lib/machines/long-running/foo /foo
rm -f /var/lib/machines/long-running/root/foo /foo

# test io.systemd.Machine.OpenRootDirectory
varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.OpenRootDirectory '{"name": ".host"}'
varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.OpenRootDirectory '{"name": "long-running"}'

# Terminating machine, otherwise acquiring image metadata by io.systemd.MachineImage.List may fail in the below.
machinectl terminate long-running
# Wait for the container to stop, otherwise acquiring image metadata by io.systemd.MachineImage.List below
# may fail.
#
# We need to wait until the systemd-nspawn process is completely stopped, as the lock is held for almost the
# entire life of the process (see the run() function in nspawn.c). This means that the machine gets
# unregistered _before_ this lock is lifted which makes `machinectl status` return non-zero EC earlier than
# we need.
timeout 30 bash -xec 'until [[ "$(systemctl show -P ActiveState systemd-nspawn@long-running.service)" == inactive ]]; do sleep .5; done'

# test io.systemd.MachineImage.List
varlinkctl --more call /run/systemd/machine/io.systemd.MachineImage io.systemd.MachineImage.List '{}' | grep 'long-running'
varlinkctl --more call /run/systemd/machine/io.systemd.MachineImage io.systemd.MachineImage.List '{}' | grep '.host'
varlinkctl call /run/systemd/machine/io.systemd.MachineImage io.systemd.MachineImage.List '{"name":"long-running"}'
varlinkctl call /run/systemd/machine/io.systemd.MachineImage io.systemd.MachineImage.List '{"name":"long-running", "acquireMetadata": "yes"}' | grep 'OSRelease'

# test io.systemd.MachineImage.Update
varlinkctl call /run/systemd/machine/io.systemd.MachineImage io.systemd.MachineImage.Update '{"name":"long-running", "newName": "long-running-renamed", "readOnly": true}'
varlinkctl call /run/systemd/machine/io.systemd.MachineImage io.systemd.MachineImage.List '{"name":"long-running-renamed"}'
varlinkctl call /run/systemd/machine/io.systemd.MachineImage io.systemd.MachineImage.List '{"name":"long-running-renamed"}' | jq '.readOnly' | grep 'true'

varlinkctl call /run/systemd/machine/io.systemd.MachineImage io.systemd.MachineImage.Update '{"name":"long-running-renamed", "newName": "long-running", "readOnly": false}'
varlinkctl call /run/systemd/machine/io.systemd.MachineImage io.systemd.MachineImage.List '{"name":"long-running"}'
varlinkctl call /run/systemd/machine/io.systemd.MachineImage io.systemd.MachineImage.List '{"name":"long-running"}' | jq '.readOnly' | grep 'false'

# test io.systemd.MachineImage.Clone
varlinkctl call /run/systemd/machine/io.systemd.MachineImage io.systemd.MachineImage.Clone '{"name":"long-running", "newName": "long-running-cloned", "readOnly": true}'
varlinkctl call /run/systemd/machine/io.systemd.MachineImage io.systemd.MachineImage.List '{"name":"long-running-cloned"}'
varlinkctl call /run/systemd/machine/io.systemd.MachineImage io.systemd.MachineImage.List '{"name":"long-running-cloned"}' | jq '.readOnly' | grep 'true'
# this is for io.systemd.MachineImage.CleanPool test
varlinkctl call /run/systemd/machine/io.systemd.MachineImage io.systemd.MachineImage.Clone '{"name":"long-running", "newName": "long-running-to-cleanup", "readOnly": true}'

# test io.systemd.MachineImage.Remove
varlinkctl call /run/systemd/machine/io.systemd.MachineImage io.systemd.MachineImage.Remove '{"name":"long-running-cloned"}'
(! varlinkctl call /run/systemd/machine/io.systemd.MachineImage io.systemd.MachineImage.List '{"name":"long-running-cloned"}')

# test io.systemd.MachineImage.SetPoolLimit
FSTYPE="$(stat --file-system --format "%T" /var/lib/machines)"
if [[ "$FSTYPE" == "btrfs" ]]; then
     varlinkctl call /run/systemd/machine/io.systemd.MachineImage io.systemd.MachineImage.SetPoolLimit '{"limit": 18446744073709551615}' # UINT64_MAX
fi

# test io.systemd.MachineImage.CleanPool
varlinkctl call /run/systemd/machine/io.systemd.MachineImage io.systemd.MachineImage.List '{"name":"long-running-to-cleanup"}'
varlinkctl --more call /run/systemd/machine/io.systemd.MachineImage io.systemd.MachineImage.CleanPool '{"mode":"all"}' | grep "long-running-to-cleanup"
(! varlinkctl call /run/systemd/machine/io.systemd.MachineImage io.systemd.MachineImage.List '{"name":"long-running-to-cleanup"}')
