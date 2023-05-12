#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

export PAGER=

CREATE_BB_CONTAINER="/usr/lib/systemd/tests/testdata/create-busybox-container"

at_exit() {
    set +e

    machinectl status long-running >/dev/null && machinectl kill --signal=KILL long-running
    mountpoint -q /var/lib/machines && timeout 10 sh -c "while ! umount /var/lib/machines; do sleep .5; done"
}

trap at_exit EXIT

# Mount tmpfs over /var/lib/machines to not pollute the image
mkdir -p /var/lib/machines
mount -t tmpfs tmpfs /var/lib/machines

# Create a couple of containers we can refer to in tests
for i in {0..4}; do
    "$CREATE_BB_CONTAINER" "/var/lib/machines/container$i"
    machinectl start "container$i"
done
# Create one "long running" container with some basic signal handling
"$CREATE_BB_CONTAINER" /var/lib/machines/long-running
cat >/var/lib/machines/long-running/sbin/init <<\EOF
#!/bin/sh -x
#
PID=0

# sh doesn't recognize RTMIN+4, so we have to use the signal number directly
trap "touch /poweroff" 38
trap "touch /reboot" INT
trap "touch /trap" TRAP
trap 'kill $PID' EXIT

# We need to wait for the sleep process asynchronously in order to allow
# bash to process signals
sleep infinity &
PID=$!
while :; do
    wait || :
done
EOF
machinectl start long-running

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

[[ "$(machinectl shell testuser@ /bin/sh -c 'echo -ne $FOO')" == "" ]]
[[ "$(machinectl shell --setenv=FOO=bar testuser@ /bin/sh -c 'echo -ne $FOO')" == "bar" ]]

[[ "$(machinectl show --property=State --value long-running)" == "running" ]]
# Equivalent to machinectl kill --signal=SIGRTMIN+4 --kill-whom=leader
rm -f /var/lib/machines/long-running/poweroff
machinectl poweroff long-running
test -e /var/lib/machines/long-running/poweroff
machinectl poweroff long-running long-running long-running
# Equivalent to machinectl kill --signal=SIGINT --kill-whom=leader
rm -f /var/lib/machines/long-running/reboot
machinectl reboot long-running
test -e /var/lib/machines/long-running/reboot
machinectl reboot long-running long-running long-running
# Skip machinectl terminate for now, as it doesn't play well with our "init"
rm -f /var/lib/machines/long-running/trap
machinectl kill --signal=SIGTRAP --kill-whom=leader long-running
test -e /var/lib/machines/long-running/trap
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
[[ "$(machinectl show-image --property=ReadOnly --value clone2)" == no ]]
machinectl read-only clone2 yes
[[ "$(machinectl show-image --property=ReadOnly --value clone2)" == yes ]]
machinectl read-only clone2 no
[[ "$(machinectl show-image --property=ReadOnly --value clone2)" == no ]]
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
dd if=/dev/zero of=/tmp/container.raw bs=1M count=32
mkfs.ext4 /tmp/container.raw
mount -o loop /tmp/container.raw /tmp/mnt
cp -r /var/lib/machines/container1/* /tmp/mnt
umount /tmp/mnt
# Try to import it, run it, export it, and re-import it
machinectl import-raw /tmp/container.raw container-raw
[[ "$(machinectl show-image --property=Type --value container-raw)" == "raw" ]]
machinectl start container-raw
machinectl export-raw container-raw /tmp/container-export.raw
machinectl import-raw /tmp/container-export.raw container-raw-reimport
[[ "$(machinectl show-image --property=Type --value container-raw-reimport)" == "raw" ]]
machinectl remove container-raw container-raw-reimport
rm -f /tmp/container{,-export}.raw

# Prepare a simple tar.gz container
tar -pczf /tmp/container.tar.gz -C /var/lib/machines/container1 .
# Try to import it, run it, export it, and re-import it
machinectl import-tar /tmp/container.tar.gz container-tar
[[ "$(machinectl show-image --property=Type --value container-tar)" == "directory" ]]
machinectl start container-tar
machinectl export-tar container-tar /tmp/container-export.tar.gz
machinectl import-tar /tmp/container-export.tar.gz container-tar-reimport
[[ "$(machinectl show-image --property=Type --value container-tar-reimport)" == "directory" ]]
machinectl remove container-tar container-tar-reimport
rm -f /tmp/container{,-export}.tar.gz

# Try to import a container directory & run it
cp -r /var/lib/machines/container1 /tmp/container.dir
machinectl import-fs /tmp/container.dir container-dir
[[ "$(machinectl show-image --property=Type --value container-dir)" == "directory" ]]
machinectl start container-dir
timeout 10 sh -c "while ! machinectl remove container-dir; do sleep .5; done"
rm -fr /tmp/container.dir

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
