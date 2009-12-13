#!/bin/sh -e
# read list of scancodes, convert hex to decimal and
# append to the atkbd force_release sysfs attribute
# $1 sysfs devpath for serioX
# $2 file with scancode list (hex or dec)

case "$2" in
	/*) scf="$2" ;;
	*)  scf="/lib/udev/keymaps/force-release/$2" ;;
esac

read attr <"/sys/$1/force_release"
while read scancode dummy; do
	case "$scancode" in
		\#*) ;;
		*)
			scancode=$(($scancode))
			attr="$attr${attr:+,}$scancode"
			;;
	esac
done <"$scf"
echo "$attr" >"/sys/$1/force_release"
