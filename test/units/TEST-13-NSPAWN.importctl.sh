#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

export PAGER=

TEST_CMDLINE="/tmp/proc-cmdline.$RANDOM"

at_exit() {
    set +e
    umount -l -R /var/lib/confexts
    rm -f /var/tmp/importtest /var/tmp/importtest2 /var/tmp/importtest.tar.gz /var/tmp/importtest2.tar.gz "$TEST_CMDLINE"
    mountpoint -q /proc/cmdline && umount /proc/cmdline
}

trap at_exit EXIT

systemctl service-log-level systemd-importd debug

# Mount tmpfs over /var/lib/confexts to not pollute the image
mkdir -p /var/lib/confexts
mount -t tmpfs tmpfs /var/lib/confexts -o mode=755

importctl
importctl --no-pager --help
importctl --version
importctl list-transfers
importctl list-transfers --no-legend --no-ask-password
importctl list-transfers -j
importctl list-images
importctl list-images --no-legend --no-ask-password
importctl list-images -j

(! importctl cancel-transfer 4711)

dd if=/dev/urandom of=/var/tmp/importtest bs=4096 count=10

importctl import-raw --class=confext /var/tmp/importtest
cmp /var/tmp/importtest /var/lib/confexts/importtest.raw
importctl export-raw --class=confext importtest /var/tmp/importtest2
cmp /var/tmp/importtest /var/tmp/importtest2

(! importctl pull-raw --class=confext file:///var/tmp/importtest)
importctl pull-raw --verify=no --class=confext file:///var/tmp/importtest importtest3
cmp /var/tmp/importtest /var/lib/confexts/importtest3.raw

tar czf /var/tmp/importtest.tar.gz -C /var/tmp importtest

importctl import-tar --class=confext /var/tmp/importtest.tar.gz importtest4
cmp /var/tmp/importtest /var/lib/confexts/importtest4/importtest

importctl export-tar --class=confext importtest4 /var/tmp/importtest2.tar.gz
importctl import-tar --class=confext /var/tmp/importtest2.tar.gz importtest5
cmp /var/tmp/importtest /var/lib/confexts/importtest5/importtest

importctl import-fs --class=confext /var/lib/confexts/importtest5 importtest6
cmp /var/tmp/importtest /var/lib/confexts/importtest6/importtest

(! importctl pull-tar --class=confext file:///var/tmp/importtest.tar.gz importtest7)
importctl pull-tar --class=confext --verify=no file:///var/tmp/importtest.tar.gz importtest7
cmp /var/tmp/importtest /var/lib/confexts/importtest7/importtest

importctl list-images
importctl list-images -j

varlinkctl call --more /run/systemd/io.systemd.Import io.systemd.Import.ListTransfers '{}' --graceful=io.systemd.Import.NoTransfers

varlinkctl call --more /run/systemd/io.systemd.Import io.systemd.Import.Pull '{"class":"confext","remote":"file:///var/tmp/importtest.tar.gz","local":"importtest8","type":"tar","verify":"no"}'
cmp /var/tmp/importtest /var/lib/confexts/importtest8/importtest

echo -n "systemd.pull=tar,confext,verify=no:importtest9:file:///var/tmp/importtest.tar.gz " > "$TEST_CMDLINE"
cat /proc/cmdline >> "$TEST_CMDLINE"
mount --bind "$TEST_CMDLINE" /proc/cmdline

cat /proc/cmdline

systemctl daemon-reload

systemctl start import0.service
cmp /var/tmp/importtest /var/lib/confexts/importtest9/importtest

# Verify generic service calls, too
varlinkctl call --more /run/systemd/io.systemd.Import io.systemd.service.Ping '{}'
varlinkctl call --more /run/systemd/io.systemd.Import io.systemd.service.SetLogLevel '{"level":"7"}'
varlinkctl call --more /run/systemd/io.systemd.Import io.systemd.service.SetLogLevel '{"level":"1"}'
varlinkctl call --more /run/systemd/io.systemd.Import io.systemd.service.SetLogLevel '{"level":"7"}'
varlinkctl call --more /run/systemd/io.systemd.Import io.systemd.service.GetEnvironment '{}'
