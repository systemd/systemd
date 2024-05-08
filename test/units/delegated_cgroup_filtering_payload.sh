#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later

mkdir /sys/fs/cgroup/system.slice/delegated-cgroup-filtering.service/the_child
/bin/sh /usr/lib/systemd/tests/testdata/units/delegated_cgroup_filtering_payload_child.sh

echo "parent_process: hello, world!"
echo "parent_process: hello, people!"
sleep 2
