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

# if we want to build SELinux support in or not.
# 0 - no SELinux support
# 1 - SELinux support
%define selinux 1 

# if we want to enable debugging support in udev.  If it is enabled, lots of 
# stuff will get sent to the debug syslog.
# 0 - debugging disabled
# 1 - debugging enabled
%define debug 0

# if we want to use the LSB version of the init script or the Redhat one
# 0 - use Redhat: etc/init.d/udev
# 1 - use LSB: etc/init.d/udev.init.LSB
%define lsb 0

# if we want to build the scsi_id "extra" package or not
# 0 - do not build the package
# 1 - build it
%define scsi_id 1

Summary: A userspace implementation of devfs
Name: udev
Version: 019
Release: 1
License: GPL
Group: Utilities/System
Source: ftp://ftp.kernel.org/pub/linux/utils/kernel/hotplug/%{name}-%{version}.tar.gz
ExclusiveOS: Linux
Vendor: Greg Kroah-Hartman <greg@kroah.com>
URL : kernel.org/pub/linux/utils/kernel/hotplug/
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
%else
	USE_LOG=false		\
%endif
%if %{dbus}
	USE_DBUS=true		\
%else
	USE_DBUS=false		\
%endif
%if %{selinux}
	USE_SELINUX=true	\
%else
	USE_SELINUX=false	\
%endif
%if %{debug}
	DEBUG=true		\
%else
	DEBUG=false		\
%endif
	EXTRAS="	\
%if %{scsi_id}
	extras/scsi_id	\
%endif
"

%install
make DESTDIR=$RPM_BUILD_ROOT install \
%if %{dbus}
	USE_DBUS=true		\
%else
	USE_DBUS=false		\
%endif
%if %{selinux}
	USE_SELINUX=true	\
%else
	USE_SELINUX=false	\
%endif
%if %{lsb}
	USE_LSB=true		\
%else
	USE_LSB=false		\
%endif
	EXTRAS="	\
%if %{scsi_id}
	extras/scsi_id	\
%endif
"

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
%doc COPYING README TODO ChangeLog HOWTO* etc/udev/udev.rules.examples docs/*
%attr(755,root,root) /sbin/udev
%attr(755,root,root) /sbin/udevinfo
%attr(755,root,root) /sbin/udevsend
%attr(755,root,root) /sbin/udevd
%attr(755,root,root) /sbin/udevtest
%attr(755,root,root) %dir /udev/
%attr(755,root,root) %dir /etc/udev/
%config(noreplace) %attr(0644,root,root) /etc/udev/udev.conf
%config(noreplace) %attr(0644,root,root) /etc/udev/udev.rules
%config(noreplace) %attr(0644,root,root) /etc/udev/udev.permissions
%attr(-,root,root) /etc/hotplug.d/default/udev.hotplug
%attr(755,root,root) /etc/init.d/udev
%attr(0644,root,root) %{_mandir}/man8/udev*.8*

%if %{dbus}
	%config(noreplace) %attr(0644,root,root) /etc/dbus-1/system.d/udev_sysbus_policy.conf
%endif

%if %{scsi_id}
	%attr(755,root,root) /sbin/scsi_id
	%config(noreplace) %attr(0644,root,root) /etc/scsi_id.config
	%attr(0644,root,root) %{_mandir}/man8/scsi_id*.8*
%endif

%changelog
* Fri Feb 27 2004 Greg Kroah-Hartman <greg@kroah.com>
- added ability to build with SELinux support

* Thu Feb 19 2004 Greg Kroah-Hartman <greg@kroah.com>
- add some more files to the documentation directory
- add ability to build scsi_id and make it the default

* Mon Feb 16 2004 Greg Kroah-Hartman <greg@kroah.com>
- fix up udevd build, as it's no longer needed to be build seperatly
- add udevtest to list of files
- more Red Hat sync ups.

* Thu Feb 12 2004 Greg Kroah-Hartman <greg@kroah.com>
- add some changes from the latest Fedora udev release.

* Mon Feb 2 2004 Greg Kroah-Hartman <greg@kroah.com>
- add udevsend, and udevd to the files
- add ability to build udevd with glibc after the rest is build with klibc

* Mon Jan 26 2004 Greg Kroah-Hartman <greg@kroah.com>
- added udevinfo to rpm
- added URL to spec file
- added udevinfo's man page

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
