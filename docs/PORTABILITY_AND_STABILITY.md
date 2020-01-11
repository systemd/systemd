---
title: Interface Portability and Stability Chart
category: Interfaces
layout: default
---

# Interface Portability And Stability Chart

systemd provides a number of APIs to applications. Below you'll find a table detailing which APIs are considered stable and how portable they are.

This list is intended to be useful for distribution and OS developers who are interested in maintaining a certain level of compatibility with the new interfaces systemd introduced, without relying on systemd itself.

In general it is our intention to cooperate through interfaces and not code with other distributions and OSes. That means that the interfaces where this applies are best reimplemented in a compatible fashion on those other operating systems. To make this easy we provide detailed interface documentation where necessary. That said, it's all Open Source, hence you have the option to a) fork our code and maintain portable versions of the parts you are interested in independently for your OS, or b) build systemd for your distro, but leave out all components except the ones you are interested in and run them without the core of systemd involved. We will try not to make this any more difficult than necessary. Patches to allow systemd code to be more portable will be accepted on case-by-case basis (essentially, patches to follow well-established standards instead of e.g. glibc or linux extensions have a very high chance of being accepted, while patches which make the code ugly or exist solely to work around bugs in other projects have a low chance of being accepted).

Many of these interfaces are already being used by applications and 3rd party code. If you are interested in compatibility with these applications, please consider supporting these interfaces in your distribution, where possible.


## General Portability of systemd and its Components

**Portability to OSes:** systemd is not portable to non-Linux systems. It makes use of a large number of Linux-specific interfaces, including many that are used by its very core. We do not consider it feasible to port systemd to other Unixes (let alone non-Unix operating systems) and will not accept patches for systemd core implementing any such portability (but hey, it's git, so it's as easy as it can get to maintain your own fork...). APIs that are supposed to be used as library code are exempted from this: it is important to us that these compile nicely on non-Linux and even non-Unix platforms, even if they might just become NOPs.

**Portability to Architectures:** It is important to us that systemd is portable to little endian as well as big endian systems. We will make sure to provide portability with all important architectures and hardware Linux runs on and are happy to accept patches for this.

**Portability to Distributions:** It is important to us that systemd is portable to all Linux distributions. However, the goal is to unify many of the needless differences between the distributions, and hence will not accept patches for certain distribution-specific work-arounds. Compatibility with the distribution's legacy should be maintained in the distribution's packaging, and not in the systemd source tree.

**Compatibility with Specific Versions of Other packages:** We generally avoid adding compatibility kludges to systemd that work around bugs in certain versions of other software systemd interfaces with. We strongly encourage fixing bugs where they are, and if that's not systemd we rather not try to fix it there. (There are very few exceptions to this rule possible, and you need an exceptionally strong case for it).


## General Portability of systemd's APIs

systemd's APIs are available everywhere where systemd is available. Some of the APIs we have defined are supposed to be generic enough to be implementable independently of systemd, thus allowing compatibility with systems systemd itself is not compatible with, i.e. other OSes, and distributions that are unwilling to fully adopt systemd.

A number of systemd's APIs expose Linux or systemd-specific features that cannot sensibly be implemented elsewhere. Please consult the table below for information about which ones these are.

Note that not all of these interfaces are our invention (but most), we just adopted them in systemd to make them more prominently implemented. For example, we adopted many Debian facilities in systemd to push it into the other distributions as well.



---



And now, here's the list of (hopefully) all APIs that we have introduced with systemd:
[[!table header="no" class="mointable" data="""
**API**  | **Type** | **Covered by [[Interface Stability Promise|http://www.freedesktop.org/wiki/Software/systemd/InterfaceStabilityPromise]]** | **Fully documented** | **Known External Consumers** | **Reimplementable Independently** | **Known Other Implementations** | **systemd Implementation portable to other OSes or non-systemd distributions
[[hostnamed|http://www.freedesktop.org/wiki/Software/systemd/hostnamed]] | D-Bus | yes | yes | GNOME | yes | [[Ubuntu|https://launchpad.net/ubuntu/+source/ubuntu-system-service]], [[Gentoo|http://www.gentoo.org/proj/en/desktop/gnome/openrc-settingsd.xml]], [[BSD|http://uglyman.kremlin.cc/gitweb/gitweb.cgi?p=systembsd.git;a=summary]] | partially
[[localed|http://www.freedesktop.org/wiki/Software/systemd/localed]] | D-Bus | yes | yes | GNOME | yes | [[Ubuntu|https://launchpad.net/ubuntu/+source/ubuntu-system-service]], [[Gentoo|http://www.gentoo.org/proj/en/desktop/gnome/openrc-settingsd.xml]], [[BSD|http://uglyman.kremlin.cc/gitweb/gitweb.cgi?p=systembsd.git;a=summary]] | partially
[[timedated|http://www.freedesktop.org/wiki/Software/systemd/timedated]] | D-Bus | yes | yes | GNOME | yes | [[Gentoo|http://www.gentoo.org/proj/en/desktop/gnome/openrc-settingsd.xml]], [[BSD|http://uglyman.kremlin.cc/gitweb/gitweb.cgi?p=systembsd.git;a=summary]] | partially
[[initrd interface|http://www.freedesktop.org/wiki/Software/systemd/InitrdInterface]] | Environment, flag files | yes | yes | dracut, [[ArchLinux|ArchLinux]] | yes | [[ArchLinux|ArchLinux]] | no
[[Container interface|http://www.freedesktop.org/wiki/Software/systemd/ContainerInterface]] | Environment, Mounts | yes | yes | libvirt/LXC | yes | - | no
[[Boot Loader interface|http://www.freedesktop.org/wiki/Software/systemd/BootLoaderInterface]] | EFI variables | yes | yes | gummiboot | yes | - | no
[[Service bus API|http://www.freedesktop.org/wiki/Software/systemd/dbus]] | D-Bus | yes | yes | system-config-services | no | - | no
[[logind|http://www.freedesktop.org/wiki/Software/systemd/logind]] | D-Bus | yes | yes | GNOME | no | - | no
[[sd-login.h API|http://0pointer.de/public/systemd-man/sd-login.html]] | C Library | yes | yes | GNOME, [[PolicyKit|PolicyKit]], ... | no | - | no
[[sd-daemon.h API|http://0pointer.de/public/systemd-man/sd-daemon.html]] | C Library or Drop-in | yes | yes | numerous | yes | - | yes
[[sd-id128.h API|http://0pointer.de/public/systemd-man/sd-id128.html]] | C Library | yes | yes | - | yes | - | no
[[sd-journal.h API|http://0pointer.de/public/systemd-man/sd-journal.html]] | C Library | yes | yes | - | maybe | - | no
[[$XDG_RUNTIME_DIR|https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html]] | Environment | yes | yes | glib, GNOME | yes | - | no
[[$LISTEN_FDS/$LISTEN_PID FD Passing|http://0pointer.de/public/systemd-man/sd_listen_fds.html]] | Environment | yes | yes | numerous (via sd-daemon.h) | yes | - | no
[[$NOTIFY_SOCKET Daemon Notifications|http://0pointer.de/public/systemd-man/sd_notify.html]] | Environment | yes | yes | a few, including udev | yes | - | no
[[argv&#91;0&#93;&#91;0&#93;='@' Logic|http://www.freedesktop.org/wiki/Software/systemd/RootStorageDaemons]] | /proc marking | yes | yes | mdadm | yes | - | no
[[Unit file format|http://0pointer.de/public/systemd-man/systemd.unit.html]] | File format | yes | yes | numerous | no | - | no
[[Journal File Format|http://www.freedesktop.org/wiki/Software/systemd/journal-files]] | File format | yes | yes | - | maybe | - | no
[[Journal Export Format|http://www.freedesktop.org/wiki/Software/systemd/export]] | File format | yes | yes | - | yes | - | no
[[Cooperation in cgroup tree|http://www.freedesktop.org/wiki/Software/systemd/PaxControlGroups]] | Treaty | yes | yes | libvirt | yes | libvirt | no
[[Password Agents|http://www.freedesktop.org/wiki/Software/systemd/PasswordAgents]] | Socket+Files | yes | yes | - | yes | - | no
[[udev multi-seat properties|http://www.freedesktop.org/wiki/Software/systemd/multiseat]] | udev Property | yes | yes | X11, gdm | no | - | no
udev session switch ACL properties | udev Property | no | no | - | no | - | no
[[CLI of systemctl,...|http://0pointer.de/public/systemd-man/systemctl.html]] | CLI | yes | yes | numerous | no | - | no
[[tmpfiles.d|https://www.freedesktop.org/software/systemd/man/tmpfiles.d.html]] | File format | yes | yes | numerous | yes | [[ArchLinux|ArchLinux]] | partially
[[sysusers.d|https://www.freedesktop.org/software/systemd/man/sysusers.d.html]] | File format | yes | yes | unknown | yes | | partially
[[/etc/machine-id|http://0pointer.de/public/systemd-man/machine-id.html]] | File format | yes | yes | D-Bus | yes | - | no
[[binfmt.d|http://0pointer.de/public/systemd-man/binfmt.d.html]] | File format | yes | yes | numerous | yes | - | partially
[[/etc/hostname|http://0pointer.de/public/systemd-man/hostname.html]] | File format | yes | yes | numerous (it's a Debian thing) | yes | Debian, [[ArchLinux|ArchLinux]] | no
[[/etc/locale.conf|http://0pointer.de/public/systemd-man/locale.conf.html]] | File format | yes | yes | - | yes | [[ArchLinux|ArchLinux]] | partially
[[/etc/machine-info|http://0pointer.de/public/systemd-man/machine-info.html]] | File format | yes | yes | - | yes | - | partially
[[modules-load.d|http://0pointer.de/public/systemd-man/modules-load.d.html]] | File format | yes | yes | numerous | yes | - | partially
[[/usr/lib/os-release|http://0pointer.de/public/systemd-man/os-release.html]] | File format | yes | yes | some | yes | Fedora, OpenSUSE, [[ArchLinux|ArchLinux]], Angstrom, Frugalware, others... | no
[[sysctl.d|http://0pointer.de/public/systemd-man/sysctl.d.html]] | File format | yes | yes | some (it's a Debian thing) | yes | procps/Debian, [[ArchLinux|ArchLinux]] | partially
[[/etc/timezone|http://0pointer.de/public/systemd-man/timezone.html]] | File format | yes | yes | numerous (it's a Debian thing) | yes | Debian | partially
[[/etc/vconsole.conf|http://0pointer.de/public/systemd-man/vconsole.conf.html]] | File format | yes | yes | - | yes | [[ArchLinux|ArchLinux]] | partially
/run | File hierarchy change | yes | yes | numerous | yes | OpenSUSE, Debian, [[ArchLinux|ArchLinux]] | no
[[Generators|http://www.freedesktop.org/wiki/Software/systemd/Generators]] | Subprocess | yes | yes | - | no | - | no
[[System Updates|http://freedesktop.org/wiki/Software/systemd/SystemUpdates]] | System Mode | yes | yes | - | no | - | no
[[Presets|http://freedesktop.org/wiki/Software/systemd/Preset]] | File format | yes | yes | - | no | - | no
Udev rules | File format | yes | yes | numerous | no | no | partially
"""]]


### Explanations

Items for which "systemd implementation portable to other OSes" is "partially" means that it is possible to run the respective tools that are included in the systemd tarball outside of systemd. Note however that this is not officially supported, so you are more or less on your own if you do this. If you are opting for this solution simply build systemd as you normally would but drop all files except those which you are interested in.

Of course, it is our intention to eventually document all interfaces we defined. If we haven't documented them for now, this is usually because we want the flexibility to still change things, or don't want 3rd party applications to make use of these interfaces already. That said, our sources are quite readable and open source, so feel free to spelunk around in the sources if you want to know more.

If you decide to reimplement one of the APIs for which "Reimplementable independently" is "no", then we won't stop you, but you are on your own.

This is not an attempt to comprehensively list all users of these APIs. We are just listing the most obvious/prominent ones which come to our mind.

Of course, one last thing I can't make myself not ask you before we finish here, and before you start reimplementing these APIs in your distribution: are you sure it's time well spent if you work on reimplementing all this code instead of just spending it on adopting systemd on your distro as well?
