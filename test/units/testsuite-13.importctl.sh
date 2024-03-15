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
    umount -l -R /var/lib/confexts
    rm -f /var/tmp/importtest /var/tmp/importtest2 /var/tmp/importtest.tar.gz /var/tmp/importtest2.tar.gz
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
