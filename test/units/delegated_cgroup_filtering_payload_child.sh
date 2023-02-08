#!/bin/sh

echo $$ >/sys/fs/cgroup/system.slice/delegated-cgroup-filtering.service/the_child/cgroup.procs

while true
do
	echo "child_process: hello, world!"
	echo "child_process: hello, people!"
    sleep .15
done
