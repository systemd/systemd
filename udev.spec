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

# if we want to enable debugging support in udev.  If it is enabled, lots of 
# stuff will get sent to the debug syslog.
# 0 - debugging disabled
# 1 - debugging enabled
%define debug 0

# if we want to build the scsi_id "extra" package or not
# 0 - do not build the package
# 1 - build it
%define scsi_id 1

# if we want to build the volume_id "extra" package or not
# 0 - do not build the package
# 1 - build it
%define volume_id 1

Summary: A userspace implementation of devfs
Name: udev
Version: 042
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
%if %{debug}
	DEBUG=true		\
%else
	DEBUG=false		\
%endif
	EXTRAS="	\
%if %{scsi_id}
	extras/scsi_id	\
%endif
%if %{volume_id}
	extras/volume_id	\
%endif
"

%install
rm -rf $RPM_BUILD_ROOT
make DESTDIR=$RPM_BUILD_ROOT install \
	EXTRAS="	\
%if %{scsi_id}
	extras/scsi_id	\
%endif
%if %{volume_id}
	extras/volume_id	\
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
%doc COPYING README TODO ChangeLog HOWTO* docs/*
%doc etc/udev/udev.rules.{examples,gentoo,redhat}
%doc etc/udev/udev.permissions.{gentoo,redhat}
%attr(755,root,root) /sbin/udev
%attr(755,root,root) /usr/bin/udevinfo
%attr(755,root,root) /sbin/udevsend
%attr(755,root,root) /sbin/udevd
%attr(755,root,root) /usr/bin/udevtest
%attr(755,root,root) /sbin/udevstart
%attr(755,root,root) %dir /udev/
%attr(755,root,root) %dir /etc/udev/
%config(noreplace) %attr(0644,root,root) /etc/udev/udev.conf
%attr(755,root,root) %dir /etc/udev/rules.d/
%attr(755,root,root) %dir /etc/udev/permissions.d/
%config(noreplace) %attr(0644,root,root) /etc/udev/rules.d/50-udev.rules
%config(noreplace) %attr(0644,root,root) /etc/udev/permissions.d/50-udev.permissions
%attr(-,root,root) /etc/hotplug.d/default/udev.hotplug
%attr(755,root,root) /etc/init.d/udev
%attr(0644,root,root) %{_mandir}/man8/udev*.8*
%attr(755,root,root) %dir /etc/dev.d/
%attr(755,root,root) %dir /etc/dev.d/net/
%attr(0755,root,root) /etc/dev.d/net/hotplug.dev

%if %{scsi_id}
	%attr(755,root,root) /sbin/scsi_id
	%config(noreplace) %attr(0644,root,root) /etc/scsi_id.config
	%attr(0644,root,root) %{_mandir}/man8/scsi_id*.8*
%endif
%if %{volume_id}
	%attr(755,root,root) /sbin/udev_volume_id
%endif

%changelog
* Fri May 14 2004 Greg Kroah-Hartman <greg@kroah.com>
- remove dbus and selinux stuff from here
- added volume_id option

* Wed Mar 24 2004 Greg Kroah-Hartman <greg@kroah.com>
- change the way dbus and selinux support is built (now an extra)

* Tue Mar 2 2004 Greg Kroah-Hartman <greg@kroah.com>
- added udevstart to the list of files installed
- udevinfo is now in /usr/bin not /sbin

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
