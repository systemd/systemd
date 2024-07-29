#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later

echo $$ >/sys/fs/cgroup/system.slice/delegated-cgroup-filtering.service/the_child/cgroup.procs

echo "child_process: hello, world!"
echo "child_process: hello, people!"
sleep .15
