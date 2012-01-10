#!/bin/sh -e

if [ -f .git/hooks/pre-commit.sample -a ! -f .git/hooks/pre-commit ] ; then
        cp -p .git/hooks/pre-commit.sample .git/hooks/pre-commit && \
        chmod +x .git/hooks/pre-commit && \
        echo "Activated pre-commit hook."
fi

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
echo "----------------------------------------------------------------"
echo "Initialized build system. For a common configuration please run:"
echo "----------------------------------------------------------------"
echo
echo "./configure CFLAGS='-g -O0' $args"
echo
