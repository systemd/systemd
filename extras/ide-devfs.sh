#!/bin/sh

# udev CALLOUT script
# return devfs-names for ide-devices
# CALLOUT, BUS="ide", PROGRAM="/etc/udev/ide-devfs.sh %k %b %n", ID="hd*", NAME="%1c", SYMLINK="%2c"

HOST=${2%\.[0-9]}
TARGET=${2#[0-9]\.}

if [ -z ${HOST#[13579]} ]; then
	HOST=`expr $HOST - 1`
	BUS="1"
else
	BUS="0"
fi

if [ -z "$3" ]; then
	MEDIA=`cat /proc/ide/$1/media`
	if [ "$MEDIA" = "cdrom" ]; then
		echo $1 ide/host$HOST/bus$BUS/target$TARGET/lun0/cd
	elif [ "$MEDIA" = "disk" ]; then
		echo $1 ide/host$HOST/bus$BUS/target$TARGET/lun0/disc
	fi
else
	echo $1 ide/host$HOST/bus$BUS/target$TARGET/lun0/part$3
fi

