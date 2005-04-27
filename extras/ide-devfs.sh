#!/bin/sh

# udev external PROGRAM script
# return devfs-names for ide-devices
# BUS="ide", KERNEL="hd*", PROGRAM="/etc/udev/ide-devfs.sh %k %b %n", NAME="%k", SYMLINK="%c{1} %c{2}"

HOST="${2%\.[0-9]}"
TARGET="${2#[0-9]\.}"

if [ -z "${HOST#[13579]}" ]; then
	HOST=$((${HOST} - 1))
	BUS="1"
else
	BUS="0"
fi

get_dev_number() {
	num=0
	DRIVE="${1%%[0-9]*}"

	for x in /proc/ide/*/media; do
		if [ -e "${x}" ]; then
			lMEDIA=`cat ${x}`
			if [ "${lMEDIA}" = "$2" ]; then
				num=$((${num} + 1))
			fi
			if [ "${x}" = "/proc/ide/${DRIVE}/media" ]; then
				break
			fi
		fi
	done
	
	echo $((${num} - 1))
}

if [ -z "$3" ] && [ -f /proc/ide/${1}/media ]; then
	MEDIA=`cat /proc/ide/${1}/media`
	if [ "${MEDIA}" = "cdrom" ]; then
		echo ide/host${HOST}/bus${BUS}/target${TARGET}/lun0/cd cdroms/cdrom`get_dev_number $1 cdrom`
	elif [ "${MEDIA}" = "floppy" ]; then
		echo ide/host${HOST}/bus${BUS}/target${TARGET}/lun0/disc floppies/floppy`get_dev_number $1 floppy`/disc
	elif [ "${MEDIA}" = "disk" ]; then
		echo ide/host${HOST}/bus${BUS}/target${TARGET}/lun0/disc discs/disc`get_dev_number $1 disk`/disc
	fi
else
	echo ide/host${HOST}/bus${BUS}/target${TARGET}/lun0/part$3 discs/disc`get_dev_number $1 disk`/part$3
fi
