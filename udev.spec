# if we want to build against the included version of klibc or not.
# 0 - do not use klibc
# 1 - use klibc
# Watch out for where the linux symlink is in the klibc part of the tarball,
# it probably is not where you want it to be.
%define klibc 1

# if we want to have logging support in or not.
# 0 - no logging  support
# 1 - logging support
# Note, it is not recommend if you use klibc to enable logging.
%define log 0

# if we want to build DBUS support in or not.
# 0 - no DBUS support
# 1 - DBUS support
%define dbus 0

# if we want to enable debugging support in udev.  If it is enabled, lots of 
# stuff will get sent to the debug syslog.
# 0 - debugging disabled
# 1 - debugging enabled
%define debug 0

# if we want to use the LSB version of the init script or the Redhat one
# 0 - use Redhat version: etc/init.d/udev
# 1 - use LSB version: etc/init.d/udev.init.LSB
%define lsb 0

Summary: A userspace implementation of devfs
Name: udev
Version: 013_bk
Release: 1
License: GPL
Group: Utilities/System
Source: ftp://ftp.kernel.org/pub/linux/utils/kernel/hotplug/%{name}-%{version}.tar.gz
ExclusiveOS: Linux
Vendor: Greg Kroah-Hartman <greg@kroah.com>
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
Prereq: /bin/sh, fileutils, hotplug

%description
udev is a implementation of devfs in userspace using sysfs and
/sbin/hotplug. It requires a 2.6 kernel to run properly.

%prep
%setup -q

%build
make CC="gcc $RPM_OPT_FLAGS"	\
%if %{klibc}
	USE_KLIBC=true		\
%endif
%if %{log}
	USE_LOG=true		\
%endif
%if %{dbus}
	USE_DBUS=true		\
%endif
%if %{debug}
	DEBUG=true		\
%endif

%install
make DESTDIR=$RPM_BUILD_ROOT install \
%if %{dbus}
	USE_DBUS=true
%endif
%if %{lsb}
	USE_LSB=true
%endif

%post
/sbin/chkconfig --add udev

%postun
if [ $1 = 0 ]; then
	/sbin/chkconfig --del udev
fi

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%doc COPYING README TODO ChangeLog
%attr(755,root,root) /sbin/udev
%attr(755,root,root) /udev/
%attr(755,root,root) /etc/udev/
%config(noreplace) %attr(0644,root,root) /etc/udev/udev.conf
%config(noreplace) %attr(0644,root,root) /etc/udev/udev.rules
%config(noreplace) %attr(0644,root,root) /etc/udev/udev.permissions
%if %{dbus}
	%config(noreplace) %attr(0644,root,root) /etc/dbus-1/system.d/udev_sysbus_policy.conf
%endif
%attr(-,root,root) /etc/hotplug.d/default/udev.hotplug
%attr(755,root,root) /etc/init.d/udev
%attr(0644,root,root) %{_mandir}/man8/udev.8*

%changelog
* Mon Jan 05 2004 Rolf Eike Beer <eike-hotplug@sf-tec.de>
- add defines to choose the init script (Redhat or LSB)

* Tue Dec 16 2003 Robert Love <rml@ximian.com>
- install the initscript and run chkconfig on it

* Tue Nov 2 2003 Greg Kroah-Hartman <greg@kroah.com>
- changes due to config file name changes

* Fri Oct 17 2003 Robert Love <rml@tech9.net>
- Make work without a build root
- Correctly install the right files
- Pass the RPM_OPT_FLAGS to gcc so we can build per the build policy
- Put some prereqs in
- Install the hotplug symlink to udev

* Mon Jul 28 2003 Paul Mundt <lethal@linux-sh.org>
- Initial spec file for udev-0.2.
