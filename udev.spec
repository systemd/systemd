Summary: A userspace implementation of devfs
Name: udev
Version: 003
Release: 1
License: GPL
Group: Utilities/System
Source: ftp://ftp.kernel.org/pub/linux/utils/kernel/hotplug/%{name}-%{version}.tar.gz
ExclusiveOS: Linux
Vendor: Greg Kroah-Hartman <greg@kroah.com>
BuildRoot: /var/tmp/%{name}-%{version}-%{release}-root

%description
udev is a implementation of devfs in userspace using sysfs and
/sbin/hotplug. It requires a 2.6 kernel to run properly.

%prep
%setup

%build
make

%install
make prefix=$RPM_BUILD_ROOT install

%clean
rm -fr $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%attr(755,root,root)/sbin/%{name}
%attr(-,root,root) %doc COPYING README TODO ChangeLog

%changelog
* Mon Jul 28 2003 Paul Mundt <lethal@linux-sh.org>
- Initial spec file for udev-0.2.

