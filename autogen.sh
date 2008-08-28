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

if test -z "$@"; then
	args="--prefix=/usr --exec-prefix= --sysconfdir=/etc"
	args="$args --with-libdir-name=$(basename $(gcc -print-multi-os-directory))"
	export CFLAGS="-g -Wall \
-Wmissing-declarations -Wmissing-prototypes \
-Wnested-externs -Wpointer-arith \
-Wpointer-arith -Wsign-compare -Wchar-subscripts \
-Wstrict-prototypes -Wshadow"
else
	args=$@
fi
echo "   configure:  $args"
echo
./configure $args
