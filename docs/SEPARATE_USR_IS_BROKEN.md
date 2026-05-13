---
title: Booting Without /usr is Broken
category: Manuals and Documentation for Users and Administrators
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Booting Without /usr is Broken

You probably discovered this page because your shiny new systemd system referred you here during boot time,
when it warned you that booting without `/usr` pre-mounted wasn't supported anymore.
And now you wonder what this all is about.
Here's an attempt of an explanation:

One thing in advance:
systemd itself is actually mostly fine with `/usr` on a separate file system that is not pre-mounted at boot time.
However, the common basic set of OS components of modern Linux machines is not, and has not been in quite some time.
And it is unlikely that this is going to be fixed any time soon, or even ever.

Most of the failures you will experience with `/usr` split off and not pre-mounted in the initramfs are graceful failures:
they won't become directly visible, however certain features become unavailable due to these failures.
Quite a number of programs these days hook themselves into the early boot process at various stages.
A popular way to do this is for example via udev rules.
The binaries called from these rules are sometimes located on `/usr/bin`, or link against libraries in `/usr/lib`,
or use data files from `/usr/share`.
If these rules fail udev will proceed with the next one,
however later on applications will then not properly detect these udev devices or features of these devices.
Here's a short, very in-comprehensive list of software we are aware of that currently are not able to provide the full set of functionality when `/usr` is split off and not pre-mounted at boot:
udev-pci-db/udev-usb-db and all rules depending on this
(using the PCI/USB database in `/usr/share`),
PulseAudio, NetworkManager, ModemManager, udisks, libatasmart, usb\_modeswitch,
gnome-color-manager, usbmuxd, ALSA, D-Bus, CUPS, Plymouth, LVM, hplip, multipath, Argyll, VMWare,
the locale logic of most programs and a lot of other stuff.

You don't believe us?
Well, here's a command line that reveals a few obvious cases of udev rules that will silently fail to work if `/usr` is split off and not pre-mounted:
`egrep 'usb-db|pci-db|FROM_DATABASE|/usr' /*/udev/rules.d/*`
-- and you find a lot more if you actually look for it.
On my fresh Fedora 15 install that's 23 obvious cases.

## The Status Quo

Due to this, many upstream developers have decided to consider the problem of a separate
`/usr` that is not mounted during early boot an outdated question,
and started to close bugs regarding these issues as WONTFIX.
We certainly cannot blame them, as the benefit of supporting this is questionable and brings a lot of additional work with it.

And let's clarify a few things:

1. **It isn't systemd's fault.** systemd mostly works fine with `/usr` on a separate file system that is not pre-mounted at boot.
2. **systemd is merely the messenger.** Don't shoot the messenger.
3. **There's no news in all of this.** The message you saw is just a statement of fact, describing the status quo.
   Things have been this way since a while.
4. **The message is merely a warning.** You can choose to ignore it.
5. **Don't blame us**, don't abuse us, it's not our fault.
We have been working on the Linux userspace since quite some time,
and simply have enough of the constant bug reports regarding these issues,
since they are actually very hard to track down because the failures are mostly graceful.
Hence we placed this warning into the early boot process of every systemd Linux system with a split off and not pre-mounted
`/usr`, so that people understand what is going on.

## Going Forward

`/usr` on its own filesystem is useful in some custom setups.
But instead of expecting the traditional Unix way to (sometimes mindlessly) distributing tools between `/usr` and `/`,
and require more and more tools to move to `/`,
we now just expect `/usr` to be pre-mounted from inside the initramfs, to be available before 'init' starts.
The duty of the minimal boot system that consisted of `/bin`, `/sbin` and `/lib` on traditional Unix,
has been taken over by the initramfs of modern Linux.
An initramfs that supports mounting `/usr` on top of `/` before it starts 'init', makes all existing setups work properly.

There is no way to reliably bring up a modern system with an empty `/usr`.
There are two alternatives to fix it: move `/usr` back to the rootfs or use an initramfs which can hide the split-off from the system.

On the Fedora distribution we have succeeded to clean up the situation and the confusion the current split between `/` and `/usr` has created.
We have moved all tools that over time have been moved to `/` back to `/usr` (where they belong),
and the root file system only contains compatibility symlinks for `/bin` and `/sbin` into `/usr`.
All binaries of the system are exclusively located within the `/usr` hierarchy.

In this new definition of `/usr`, the directory can be mounted read-only by default,
while the rootfs may be either read-write or read-only (for stateless systems) and contains only the empty mount point directories,
compat-symlinks to `/usr` and the host-specific data like `/etc`, `/root`, `/srv`.
In comparison to today's setups, the rootfs will be very small.
The host-specific data will be properly separated from the installed operating system.
The new `/usr` could also easily be shared read-only across several systems.
Such a setup would be more efficient, can provide additional security, is more flexible to use,
provides saner options for custom setups, and is much simpler to setup and maintain.

For more information on this please continue to [The Case for the /usr Merge](/THE_CASE_FOR_THE_USR_MERGE).
