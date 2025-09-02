#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later

echo $$ >/sys/fs/cgroup/system.slice/delegated-cgroup-filtering.service/the_child/cgroup.procs

echo "child_process: hello, world!"
echo "child_process: hello, people!"

# If the service finishes extremely fast, journald cannot find the source of the
# stream. Hence, we need to call 'journalctl --sync' before service finishes.
journalctl --sync
