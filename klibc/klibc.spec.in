%define _rpmdir rpms
%define _builddir .

Summary: A minimal libc subset for use with initramfs.
Name: klibc
Version: 0.89
Release: 1
License: BSD/GPL
Group: Development/Libraries
URL: http://www.zytor.com/klibc
Source: /dev/null
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Packager: Bryan O'Sullivan <bos@serpentine.com>
Prefix: /usr
Vendor: Starving Linux Artists

%description
%{name} is intended to be a minimalistic libc subset for use with
initramfs.  It is deliberately written for small size, minimal
entanglement, and portability, not speed.  It is definitely a work in
progress, and a lot of things are still missing.

%package kernheaders
Summary: Kernel headers used during the build of klibc.
Group: Development/Libraries

%description kernheaders
This package contains the set of kernel headers that were required to
build %{name} and the utilities that ship with it.  This may or may
not be a complete enough set to build other programs that link against
%{name}.  If in doubt, use real kernel headers instead.

%package utils
Summary: Small statically-linked utilities built with klibc.
Group: Utilities/System

%description utils

This package contains a collection of programs that are statically
linked against klibc.  These duplicate some of the functionality of a
regular Linux toolset, but are typically much smaller than their
full-function counterparts.  They are intended for inclusion in
initramfs images and embedded systems.

%prep
if [ ! -L linux ]; then
    echo "*** You must have a symlink named linux to build klibc" 1>&2
    exit 1
fi
if [ ! -f linux/include/asm/page.h ]; then
    echo "*** You need to 'make prepare' in the linux tree before building klibc" 1>&2
    exit 1
fi
mkdir -p %{buildroot} %{_rpmdir}

%build
make

%install
rm -rf %{buildroot}

dest=%{buildroot}/%{prefix}
lib=$dest/%{_lib}/klibc
inc=$dest/include/klibc
exe=$dest/libexec/klibc
doc=$dest/share/doc/%{name}-%{version}
udoc=$dest/share/doc/%{name}-utils-%{version}

# First, the library.

install -dD -m 755 $lib $inc/kernel $exe $doc $udoc
install -m 755 klibc/klibc.so $lib
install -m 644 klibc/libc.a $lib
install -m 644 klibc/crt0.o $lib
install -m 644 klibc/libc.so.hash $lib
ln $lib/klibc.so $lib/libc.so
ln $lib/klibc.so $lib/klibc-$(cat $lib/libc.so.hash).so

# Next, the generated binaries.

install -m 755 ash/sh $exe
install -m 755 gzip/gzip $exe
ln $exe/gzip $exe/gunzip
ln $exe/gzip $exe/zcat
install -m 755 ipconfig/ipconfig $exe
install -m 755 kinit/kinit $exe
install -m 755 nfsmount/nfsmount $exe
for i in chroot dd fstype mkdir mkfifo mount umount; do
    install -m 755 utils/$i $exe
done

# The docs.

install -m 444 README $doc
install -m 444 klibc/README $doc/README.klibc
install -m 444 klibc/arch/README $doc/README.klibc.arch

install -m 444 gzip/COPYING $udoc/COPYING.gzip
install -m 444 gzip/README $udoc/README.gzip
install -m 444 ipconfig/README $udoc/README.ipconfig
install -m 444 kinit/README $udoc/README.kinit

# Finally, the include files.

bitsize=$(make --no-print-directory -C klibc bitsize)
cp --parents $(find klibc/include \( -name CVS -o -name SCCS \) -prune \
    -o -name '*.h' -print) $inc
mv $inc/klibc $inc/klibc.$$
mv $inc/klibc.$$/include/* $inc
mv $inc/bits$bitsize/bitsize $inc
rm -rf $inc/klibc.$$ $inc/bits[0-9]*
pushd klibc/arch/%{_arch}/include
cp --parents -f $(find . \( -name CVS -o -name SCCS \) -prune \
    -o -name '*.h' -print) $inc
popd

# Yeugh.  Find the transitive closure over all kernel headers included
# by klibc, and copy them into place.

find . -name '.*.d' | xargs -r sed -e 's,[ \t][ \t]*,\n,g' | sed -n -e 's,^\.\./linux/include/,,p' | sort | uniq | (cd linux/include && xargs -ri cp --parents '{}' $inc/kernel)

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%docdir %{prefix}/share/doc/%{name}-%{version}
%{prefix}/%{_lib}/klibc
%dir %{prefix}/include/klibc
%{prefix}/include/klibc/*.h
%{prefix}/include/klibc/arpa
%{prefix}/include/klibc/bitsize
%{prefix}/include/klibc/klibc
%{prefix}/include/klibc/net
%{prefix}/include/klibc/netinet
%{prefix}/include/klibc/sys
%{prefix}/share/doc/%{name}-%{version}

%files kernheaders
%defattr(-,root,root,-)
%{prefix}/include/klibc/kernel

%files utils
%defattr(-,root,root,-)
%{prefix}/libexec/klibc
%docdir %{prefix}/share/doc/%{name}-utils-%{version}
%{prefix}/share/doc/%{name}-utils-%{version}

%changelog
* Sat Nov 29 2003 Bryan O'Sullivan <bos@serpentine.com> - 
- Initial build.
