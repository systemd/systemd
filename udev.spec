Summary: A userspace implementation of devfs
Name: udev
Version: 009_bk
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
make CC="gcc $RPM_OPT_FLAGS"

%install
make DESTDIR=$RPM_BUILD_ROOT install

%post
/sbin/chkconfig --add udev

%postun
if [ $1 = 0 ]; then
	/sbin/chkconfig --del udev
fi

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(0644,root,root)
%doc COPYING README TODO ChangeLog
%attr(755,root,root) /sbin/udev
%attr(755,root,root) /udev/
%attr(755,root,root) /etc/udev/
%attr(0644,root,root) /etc/udev/udev.conf
%attr(0644,root,root) /etc/udev/udev.rules
%attr(0644,root,root) /etc/udev/udev.permissions
%attr(-,root,root) /etc/hotplug.d/default/udev.hotplug
%attr(755,root,root) /etc/init.d/udev
%attr(0644,root,root) %{_mandir}/man8/udev.8*

%changelog
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

