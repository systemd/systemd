#!/bin/sh

# udev CALLOUT script
# return devfs-names for ide-devices
# CALLOUT, BUS="ide", PROGRAM="/etc/udev/ide-devfs.sh %k %b %n", ID="hd*", NAME="%1c", SYMLINK="%2c %3c"

HOST="${2%\.[0-9]}"
TARGET="${2#[0-9]\.}"

if [ -z "${HOST#[13579]}" ]; then
	HOST=`expr ${HOST} - 1`
	BUS="1"
else
	BUS="0"
fi

get_dev_number() {
	local x=
	local num=0
	local MEDIA=
	local DRIVE="${1%[0-9]*}"

	for x in /proc/ide/*/media; do
		if [ -e "${x}" ]; then
			MEDIA=`cat ${x}`
			if [ "${MEDIA}" = "$2" ]; then
				num=`expr ${num} + 1`
			fi
			if [ "${x}" = "/proc/ide/${DRIVE}/media" ]; then
				break
			fi
		fi
	done
	
	echo `expr ${num} - 1`
}

if [ -z "$3" ]; then
	MEDIA=`cat /proc/ide/${1}/media`
	if [ "${MEDIA}" = "cdrom" ]; then
		echo ${1} ide/host${HOST}/bus${BUS}/target${TARGET}/lun0/cd cdroms/cdrom`get_dev_number $1 cdrom`
	elif [ "${MEDIA}" = "disk" ]; then
		echo $1 ide/host${HOST}/bus${BUS}/target${TARGET}/lun0/disc discs/disc`get_dev_number $1 disk`/disc
	fi
else
	echo $1 ide/host${HOST}/bus${BUS}/target${TARGET}/lun0/part$3 discs/disc`get_dev_number $1 disk`/part$3
fi
