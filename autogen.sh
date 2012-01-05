#!/usr/bin/env sh

set -e

gtkdocize
autoreconf --install --symlink

libdir() {
	echo $(cd $1/$(gcc -print-multi-os-directory); pwd)
}

args="\
--prefix=/usr \
--with-rootprefix= \
--sysconfdir=/etc \
--bindir=/sbin \
--libdir=$(libdir /usr/lib) \
--with-rootlibdir=$(libdir /lib) \
--libexecdir=/lib \
--with-systemdsystemunitdir=/lib/systemd/system \
--with-selinux \
--enable-gtk-doc"

echo
echo "---------------------------------------------------------------------"
echo "Initialized udev build system. For a common configuration please run:"
echo "---------------------------------------------------------------------"
echo
echo "# ./configure $args"
echo
