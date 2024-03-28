---
title: systemd Optimizations
category: Documentation for Developers
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# systemd Optimizations

_So you are working on a Linux distribution or appliance and need very fast boot-ups?_

systemd can already offer boot times of < 1s for the Core OS (userspace only, i.e. only the bits controlled by systemd) and < 2s for a complete up-to-date desktop environments on simpler (but modern, i.e. SSDs) laptops if configured properly (examples: [http://git.fenrus.org/tmp/bootchart-20120512-1036.svg](http://git.fenrus.org/tmp/bootchart-20120512-1036.svg)).

In this page we want to suggest a couple of ideas how to achieve that, and if the resulting boot times do not suffice where we believe room for improvements are that we'd like to see implemented sooner or later.

If you are interested in investing engineering manpower in systemd to get to even shorter boot times, this list hopefully includes a few good suggestions to start with.

Of course, before optimizing you should instrument the boot to generate profiling data, so make sure you know your way around with systemd-bootchart, systemd-analyze and pytimechart! Optimizations without profiling are premature optimizations!

Note that systemd's fast performance is a side effect of its design but wasn't the primary design goal.
As it stands now systemd (and Fedora using it) has been optimized very little and still has a lot of room for improvements. There are still many low hanging fruits to pick!

We are very interested in merging optimization work into systemd upstream.
Note however that we are careful not to merge work that would drastically limit the general purpose usefulness or reliability of our code, or that would make systemd harder to maintain.
So in case you work on optimizations for systemd, try to keep your stuff mainlineable. If in doubt, ask us.

The distributions have adopted systemd to varying levels.
While there are many compatibility scripts in the boot process on Debian for example, Fedora has much less (but still too many).

For better performance consider disabling these scripts, or using a different distribution.
It is our intention to optimize the upstream distributions by default (in particular Fedora) so that these optimizations won't be necessary. However, this will take some time, especially since making these changes is often not trivial when the general purpose usefulness cannot be compromised.

What you can optimize (locally) without writing any code:

1. Make sure not to use any fake block device storage technology such as LVM (as installed by default by various distributions, including Fedora) they result in the systemd-udev-settle.service unit to be pulled in. Settling device enumeration is slow, racy and mostly obsolete. Since LVM (still) hasn't been updated to handle Linux' event based design properly, settling device enumeration is still required for it, but it will slow down boot substantially.
On Fedora, use "systemctl mask fedora-wait-storage.service fedora-storage-init-late.service fedora-storage-init.service" to get rid of all those storage technologies.
Of course, don't try this if you actually installed your system with LVM. (The only fake block device storage technology that currently handles this all properly and doesn't require settling device enumerations is LUKS disk encryption.)

2. Consider bypassing the initrd, if you use one.
On Fedora, make sure to install the OS on a plain disk without encryption, and without LVM/RAID/... (encrypted /home is fine) when doing this.
Then, simply edit grub.conf and remove the initrd from your configuration, and change the root= kernel command line parameter so that it uses kernel device names instead of UUIDs, i.e. "root=sda5" or what is appropriate for your system.
Also specify the root FS type with "rootfstype=ext4" (or as appropriate).
Note that using kernel devices names is not really that nice if you have multiple hard disks, but if you are doing this for a laptop (i.e. with a single hdd), this should be fine.
Note that you shouldn't need to rebuild your kernel in order to bypass the initrd.
Distribution kernels (at least Fedora's) work fine with and without initrd, and systemd supports both ways to be started.

3. Consider disabling SELinux and auditing.
We recommend leaving SELinux on, for security reasons, but truth be told you can save 100ms of your boot if you disable it.
Use selinux=0 on the kernel cmdline.

4. Consider disabling Plymouth. If userspace boots in less than 1s, a boot splash is hardly useful, hence consider passing plymouth.enable=0 on the kernel command line.
Plymouth is generally quite fast, but currently still forces settling device enumerations for graphics cards, which is slow.
Disabling plymouth removes this bit of the boot.

5. Consider uninstalling syslog. The journal is used anyway on newer systemd systems, and is usually more than sufficient for desktops, and embedded, and even many servers.
Just uninstall all syslog implementations and remember that "journalctl" will get you a pixel perfect copy of the classic /var/log/messages message log.
To make journal logs persistent (i.e. so that they aren't lost at boot) make sure to run "mkdir -p /var/log/journal".

6. Consider masking a couple of redundant distribution boot scripts, that artificially slow down the boot. For example, on Fedora it's a good idea to mask fedora-autoswap.service fedora-configure.service fedora-loadmodules.service fedora-readonly.service.
Also remove all LVM/RAID/FCOE/iSCSI related packages which slow down the boot substantially even if no storage of the specific kind is used (and if these RPMs can't be removed because some important packages require them, at least mask the respective services).

7. Console output is slow. So if you measure your boot times and ship your system, make sure to use "quiet" on the command line and disable systemd debug logging (if you enabled it before).

8. Consider removing cron from your system and use systemd timer units instead.
Timer units currently have no support for calendar times (i.e. cannot be used to spawn things "at 6 am every Monday", but can do "run this every 7 days"), but for the usual /etc/cron.daily/, /etc/cron.weekly/, ... should be good enough, if the time of day of the execution doesn't matter (just add four small service and timer units for supporting these dirs. Eventually we might support these out of the box, but until then, just write your own scriplets for this).

9. If you work on an appliance, consider disabling readahead collection in the shipped devices, but leave readahead replay enabled.

10. If you work on an appliance, make sure to build all drivers you need into the kernel, since module loading is slow.
If you build a distribution at least built all the stuff 90% of all people need into your kernel, i.e. at least USB, AHCI and HDA!

11. If it works, use libahci.ignore_sss=1 when booting.

12. Use a modern desktop that doesn't pull in ConsoleKit anymore. For example GNOME 3.4.

14. Get rid of a local MTA, if you are building a desktop or appliance.
I.e. on Fedora remove the sendmail RPMs which are (still!) installed by default.

15. If you build an appliance, don't forget that various components of systemd are optional and may be disabled during build time, see "./configure --help" for details.
For example, get rid of the virtual console setup if you never have local console users (this is a major source of slowness, actually).
In addition, if you never have local users at all, consider disabling logind. And there are more components that are frequently unnecessary on appliances.

16. This goes without saying: the boot-up gets faster if you started less stuff at boot.
So run "systemctl" and check if there's stuff you don't need and disable it, or even remove its package.

17. Don't use debug kernels. Debug kernels are slow.
Fedora exclusively uses debug kernels during the development phase of each release.
If you care about boot performance, either recompile these kernels with debugging turned off or wait for the final distribution release.
It's a drastic difference. That also means that if you publish boot performance data of a Fedora pre-release distribution you are doing something wrong. ;-) So much about the basics of how to get a quick boot.
Now, here's an incomprehensive list of things we'd like to see improved in systemd (and elsewhere) over short or long and need a bit of hacking (sometimes more, and sometimes less):

18. Get rid of systemd-cgroups-agent.
Currently, whenever a systemd cgroup runs empty a tool "systemd-cgroups-agent" is invoked by the kernel which then notifies systemd about it.
The need for this tool should really go away, which will save a number of forked processes at boot, and should make things faster (especially shutdown).
This requires introduction of a new kernel interface to get notifications for cgroups running empty, for example via fanotify() on cgroupfs.

19. Make use of EXT4_IOC_MOVE_EXT in systemd's readahead implementation.
This allows reordering/defragmentation of the files needed for boot.
According to the data from [http://e4rat.sourceforge.net/](http://e4rat.sourceforge.net/) this might shorten the boot time to 40%.
Implementation is not trivial, but given that we already support btrfs defragmentation and example code for this exists (e4rat as linked) should be fairly straightforward.

20. Compress readahead pack files with XZ or so.Since boot these days tends to be clearly IO bound (and not CPU bound) it might make sense to reduce the IO load for the pack file by compressing it. Since we already have a dependency on XZ we'd recommend using XZ for this.

21. Update the readahead logic to also precache directories (in addition to files).

22. Improve a couple of algorithms in the unit dependency graph calculation logic, as well as unit file loading.
For example, right now when loading units we match them up with a subset of the other loaded units in order to add automatic dependencies between them where appropriate.
Usually the set of units matched up is small, but the complexity is currently O(n^2), and this could be optimized. Since unit file loading and calculations in the dependency graphs is the only major, synchronous, computation-intensive bit of PID 1, and is executed before any services are started this should bring relevant improvements, especially on systems with big dependency graphs.

23. Add socket activation to X. Due to the special socket allocation semantics of X this is useful only for display :0. This should allow parallelization of X startup with its clients.

24. The usual housekeeping: get rid of shell-based services (i.e. SysV init scripts), replace them with unit files.
Don't make use of Type=forking and ordering dependencies if possible, use socket activation with Type=simple instead.
This allows drastically better parallelized start-up for your services. Also, if you cannot use socket activation, at least consider patching your services to support Type=notify in place of Type=forking. Consider making seldom used services activated on-demand (for example, printer services), and start frequently used services already at boot instead of delaying them until they are used.

25. Consider making use of systemd for the session as well, the way Tizen is doing this.
This still needs some love in systemd upstream to be a smooth ride, but we definitely would like to go this way sooner or later, even for the normal desktops.

26. Add an option for service units to temporarily bump the CPU and IO priority of the startup code of important services.
Note however, that we assume that this will not bring much and hence recommend looking into this only very late.
Since boot-up tends to be IO bound, solutions such as readahead are probably more interesting than prioritizing service startup IO. Also, this would probably always require a certain amount of manual configuration since determining automatically which services are important is hard (if not impossible), because we cannot track properly which services other services wait for.

27. Same as the previous item, but temporarily lower the CPU/IO priority of the startups part of unimportant leaf services.
This is probably more useful than 11 as it is easier to determine which processes don't matter.

28. Add a kernel sockopt for AF_UNIX to increase the maximum datagram queue length for SOCK_DGRAM sockets.
This would allow us to queue substantially more logging datagrams in the syslog and journal sockets, and thus move the point where syslog/journal clients have to block before their message writes finish much later in the boot process.
The current kernel default is rather low with 10. (As a temporary hack it is possible to increase /proc/sys/net/unix/max_dgram_qlen globally, but this has implications beyond systemd, and should probably be avoided.) The kernel patch to make this work is most likely trivial.
In general, this should allow us to improve the level of parallelization between clients and servers for AF_UNIX sockets of type SOCK_DGRAM or SOCK_SEQPACKET. Again: the list above contains things we'd like to see in systemd anyway.
We didn't do much profiling for these features, but we have enough indication to assume that these bits will bring some improvements.
But yeah, if you work on this, keep your profiling tools ready at all times.
