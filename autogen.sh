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

args="$args \
--prefix=/usr \
--sysconfdir=/etc \
--libdir=$(libdir /usr/lib) \
--with-selinux \
--enable-gtk-doc"

if [ -L /bin ]; then
args="$args \
--libexecdir=/usr/lib \
--with-systemdsystemunitdir=/usr/lib/systemd/system \
"
else
args="$args \
--with-rootprefix= \
---with-rootlibdir=$(libdir /lib) \
--bindir=/sbin \
--libexecdir=/lib \
--with-systemdsystemunitdir=/lib/systemd/system \
"
fi

echo
echo "----------------------------------------------------------------"
echo "Initialized build system. For a common configuration please run:"
echo "----------------------------------------------------------------"
echo
echo "./configure CFLAGS='-g -O1' $args"
echo
