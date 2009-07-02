#!/bin/sh -e

FIRMWARE_DIRS="/lib/firmware/updates/$(uname -r) /lib/firmware/updates \
               /lib/firmware/$(uname -r) /lib/firmware"

err() {
	echo "$@" >&2
	logger -t "${0##*/}[$$]" "$@" 2>/dev/null || true
}

if [ ! -e /sys$DEVPATH/loading ]; then
	err "udev firmware loader misses sysfs directory"
	exit 1
fi

for DIR in $FIRMWARE_DIRS; do
	[ -e "$DIR/$FIRMWARE" ] || continue
	echo 1 > /sys$DEVPATH/loading
	cat "$DIR/$FIRMWARE" > /sys$DEVPATH/data
	echo 0 > /sys$DEVPATH/loading
	exit 0
done

echo -1 > /sys$DEVPATH/loading
err "Cannot find  firmware file '$FIRMWARE'"
mkdir -p /dev/.udev/firmware-missing
file=$(echo "$FIRMWARE" | sed 's:/:\\x2f:g')
ln -s -f "$DEVPATH" /dev/.udev/firmware-missing/$file
exit 1
