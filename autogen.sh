#!/bin/sh -e

gtkdocize
autoreconf --install --symlink

CFLAGS="-g -Wall \
-Wmissing-declarations -Wmissing-prototypes \
-Wnested-externs -Wpointer-arith \
-Wpointer-arith -Wsign-compare -Wchar-subscripts \
-Wstrict-prototypes -Wshadow \
-Wformat=2 -Wtype-limits"

libdirname=$(basename $(cd /lib/$(gcc -print-multi-os-directory); pwd))
args="--prefix=/usr --exec-prefix= --sysconfdir=/etc \
--libdir=/usr/$libdirname --with-libdir-name=$libdirname \
--with-selinux --enable-gtk-doc --enable-extras"

export CFLAGS="$CFLAGS -O2"
./configure $args $@
