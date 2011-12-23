#!/bin/sh -e

gtkdocize
autoreconf --install --symlink

MYCFLAGS="-g -Wall \
-Wmissing-declarations -Wmissing-prototypes \
-Wnested-externs -Wpointer-arith \
-Wpointer-arith -Wsign-compare -Wchar-subscripts \
-Wstrict-prototypes -Wshadow \
-Wformat-security -Wtype-limits"

case "$CFLAGS" in
	*-O[0-9]*)
		;;
	*)
		MYCFLAGS="$MYCFLAGS -O2"
		;;
esac

libdir() {
	echo $(cd $1/$(gcc -print-multi-os-directory); pwd)
}

args="--prefix=/usr \
--sysconfdir=/etc \
--bindir=/sbin \
--sbindir=/sbin \
--libdir=$(libdir /usr/lib) \
--with-rootlibdir=$(libdir /lib) \
--libexecdir=/lib/udev \
--with-systemdsystemunitdir=/lib/systemd/system
--with-selinux \
--enable-gtk-doc"

./configure $args CFLAGS="${CFLAGS} ${MYCFLAGS}" $@
