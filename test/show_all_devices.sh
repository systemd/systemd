#! /bin/bash
#
# Directory where sysfs is mounted
SYSFS_DIR=/sys

# handle block devices and their partitions
for i in ${SYSFS_DIR}/block/*; do
	# each drive
	echo ${i#${SYSFS_DIR}/block/}

	# each partition, on each device
	for j in $i/*; do
		if [ -f $j/dev ]; then
			echo ${j#${SYSFS_DIR}} | cut --delimiter='/' --fields=4-
		fi
	done
done

# all other device classes
for i in ${SYSFS_DIR}/class/*; do
	for j in $i/*; do
		if [ -f $j/dev ]; then
			echo ${j#${SYSFS_DIR}} | cut --delimiter='/' --fields=4-
		fi
	done
done

