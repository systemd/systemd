#! /bin/bash
#

# Check for missing binaries (stale symlinks should not happen)
UDEV_BIN=../wait_for_sysfs
test -x $UDEV_BIN || exit 5

# Directory where sysfs is mounted
SYSFS_DIR=/sys

run_udev () {
	# handle block devices and their partitions
	for i in ${SYSFS_DIR}/block/*; do
		# add each drive
		export DEVPATH=${i#${SYSFS_DIR}}
		$UDEV_BIN block

		# add each partition, on each device
		for j in $i/*; do
			if [ -f $j/dev ]; then
				export DEVPATH=${j#${SYSFS_DIR}}
				$UDEV_BIN block
			fi
		done
	done
	# all other device classes
	for i in ${SYSFS_DIR}/class/*; do
		# try adding empty classes, just to test stuff...
		export DEVPATH=${i#${SYSFS_DIR}}
		CLASS=`echo ${i#${SYSFS_DIR}} | cut --delimiter='/' --fields=3-`
		$UDEV_BIN $CLASS

		for j in `ls $i/`; do
			x=$i/$j
			export DEVPATH=${x#${SYSFS_DIR}}
			CLASS=`echo ${i#${SYSFS_DIR}} | \
				cut --delimiter='/' --fields=3-`
			$UDEV_BIN $CLASS
		done
	done
}

export ACTION=add
run_udev
