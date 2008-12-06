#!/bin/sh -e

(autoconf --version) < /dev/null > /dev/null 2>&1 || {
	echo
	echo "You must have autoconf installed to generate the build system."
	echo
	exit 1
}
(libtoolize --version) < /dev/null > /dev/null 2>&1 || {
	echo
	echo "You must have libtool installed to generate the build system."
	echo
	exit 1
}
(autoheader --version) < /dev/null > /dev/null 2>&1 || {
	echo
	echo "You must have autoheader installed to generate the build system."
	echo
	exit 1
}
(automake --version) < /dev/null > /dev/null 2>&1 || {
	echo
	echo "You must have automake installed to generate the build system."
	echo
	exit 1
}

test -f udev/udevd.c || {
	echo "You must run this script in the top-level source directory"
	exit 1
}

echo "   aclocal:    $(aclocal --version | head -1)"
aclocal
echo "   autoconf:   $(autoconf --version | head -1)"
autoconf
echo "   libtool:   $(automake --version | head -1)"
libtoolize --force
echo "   autoheader: $(autoheader --version | head -1)"
autoheader
echo "   automake:   $(automake --version | head -1)"
automake --add-missing

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
		find . -name Makefile.in | xargs -r rm
		rm -f depcomp aclocal.m4 config.h.in configure install-sh
		rm -f missing config.guess config.sub ltmain.sh
		exit 0
		;;
	*)
		echo "Usage: $0 [--install|--devel|--clean]"
		exit 1
		;;
esac
