#!/bin/sh -e
#
# Copyright (c) 2004 Marco d'Itri <md@linux.it>
# Copyright (c) 2004 Piotr Roszatycki <dexter@debian.org>
#
# Usage:
# KERNEL="cciss!*", PROGRAM="/etc/udev/scripts/raid-devfs.sh %k", NAME="%c{1}", SYMLINK="%k"
# KERNEL="ida!*",   PROGRAM="/etc/udev/scripts/raid-devfs.sh %k", NAME="%c{1}", SYMLINK="%k"
# KERNEL="rd!*",    PROGRAM="/etc/udev/scripts/raid-devfs.sh %k", NAME="%c{1}", SYMLINK="%k"

get_dev_number_cciss() {
  grep '^cciss/' /proc/driver/cciss/* | cat -n | \
    sed -n "/cciss\/$1:/s/cciss.*//p"
}

get_dev_number_ida() {
  grep '^ida/' /proc/driver/cpqarray/* | cat -n | \
    sed -n "/ida\/$1:/s/ida.*//p"
}

get_dev_number_rd() {
  grep '^ */dev/rd/' /proc/rd/*/initial_status | cat -n | \
    sed -n "/rd\/$1:/s/\/dev\/rd.*//p"
}

get_dev_number() {
    dev=$1
    num=$(eval $(echo get_dev_number_$TYPE $dev))
    [ "$num" ] || exit 1
    echo $(($num - 1))
}

TYPE=${1%%/*}
NAME=${1#*/}

# abort if there was no match
[ "$TYPE" != "$1" ] || exit 1

case "$NAME" in
    *p*)
	LONG_NAME=disc$(get_dev_number ${NAME%%p*})/part${NAME##*p}
	;;
    *)
	LONG_NAME=disc$(get_dev_number $NAME)/disc
	;;
esac

echo "$TYPE/$LONG_NAME"
exit 0

