#!/bin/sh -e

gtkdocize
autoreconf --install --symlink

MYCFLAGS="-g -Wall \
-Wmissing-declarations -Wmissing-prototypes \
-Wnested-externs -Wpointer-arith \
-Wpointer-arith -Wsign-compare -Wchar-subscripts \
-Wstrict-prototypes -Wshadow \
-Wformat=2 -Wtype-limits"

case "$CFLAGS" in
	*-O[0-9]*)
		;;
	*)
		MYCFLAGS="$MYCFLAGS -O2"
		;;
esac

libdirname=$(basename $(cd /lib/$(gcc -print-multi-os-directory); pwd))
args="--prefix=/usr --exec-prefix= --sysconfdir=/etc \
--libdir=/usr/$libdirname --with-libdir-name=$libdirname \
--with-selinux --enable-gtk-doc"

export CFLAGS="$CFLAGS $MYCFLAGS"
./configure $args $@
