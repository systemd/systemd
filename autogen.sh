#!/bin/sh -e

autoreconf -i

CFLAGS="-g -Wall \
-Wmissing-declarations -Wmissing-prototypes \
-Wnested-externs -Wpointer-arith \
-Wpointer-arith -Wsign-compare -Wchar-subscripts \
-Wstrict-prototypes -Wshadow"
args="--prefix=/usr --exec-prefix= --sysconfdir=/etc --with-selinux"
libdir=$(basename $(cd /lib/$(gcc -print-multi-os-directory); pwd))

case "$1" in
	*install|"")
		args="$args --with-libdir-name=$libdir"
		export CFLAGS="$CFLAGS -O2"
		echo "   configure:  $args"
		echo
		./configure $args
		;;
	*devel)
		args="$args --enable-debug --with-libdir-name=$libdir"
		export CFLAGS="$CFLAGS -O0"
		echo "   configure:  $args"
		echo
		./configure $args
		;;
	*clean)
		./configure
		make maintainer-clean
		git clean -f -X
		exit 0
		;;
	*)
		echo "Usage: $0 [--install|--devel|--clean]"
		exit 1
		;;
esac
