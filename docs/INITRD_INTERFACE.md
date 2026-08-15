---
title: Initrd Interface
category: Interfaces
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---


# The initrd Interface of systemd

The Linux initrd mechanism (short for "initial RAM disk", also known as
"initramfs") refers to a small file system archive that is unpacked by the
kernel and contains the first userspace code that runs. It typically finds and
transitions into the actual root file system to use. systemd supports both
initrd and initrd-less boots. If an initrd is used, it is a good idea to pass a
few bits of runtime information from the initrd to systemd in order to avoid
duplicate work and to provide performance data to the administrator. In this
page we attempt to roughly describe the interfaces that exist between the
initrd and systemd. These interfaces are currently used by
[mkosi](https://github.com/systemd/mkosi)-generated initrds, dracut and the
Arch Linux initrds.

* The initrd should mount `/run/` as a tmpfs and pass it pre-mounted when
  jumping into the main system when executing systemd. The mount options should
  be `mode=0755,nodev,nosuid,strictatime`.

* It's highly recommended that the initrd also mounts `/usr/` (if split off) as
  appropriate and passes it pre-mounted to the main system, to avoid the
  problems described in [Booting without /usr is Broken](/SEPARATE_USR_IS_BROKEN).

* If the executable `/run/initramfs/shutdown` exists systemd will use it to
  jump back into the initrd on shutdown. `/run/initramfs/` should be a usable
  initrd environment to which systemd will pivot back and the `shutdown`
  executable in it should be able to detach all complex storage that for
  example was needed to mount the root file system. It's the job of the initrd
  to set up this directory and executable in the right way so that this works
  correctly. The shutdown binary is invoked with the shutdown verb as `argv[1]`,
  optionally followed (in `argv[2]`, `argv[3]`, …) systemd's original command
  line options, for example `--log-level=` and similar.

* Storage daemons run from the initrd should follow the guide on
  [systemd and Storage Daemons for the Root File System](/ROOT_STORAGE_DAEMONS)
  to survive properly from the boot initrd all the way to the point where
  systemd jumps back into the initrd for shutdown.

One last clarification: we use the term _initrd_ very generically here
describing any kind of early boot file system, regardless whether that might be
implemented as an actual ramdisk, ramfs or tmpfs. We recommend using _initrd_
in this sense as a term that is unrelated to the actual backing technologies
used.

## Using systemd inside an initrd

It is also possible and recommended to implement the initrd itself based on
systemd. Here are a few terse notes:

* Provide `/etc/initrd-release` in the initrd image. The idea is that it
  follows the same format as the usual `/etc/os-release` but describes the
  initrd implementation rather than the OS. systemd uses the existence of this
  file as a flag whether to run in initrd mode, or not.

* When run in initrd mode, systemd and its components will read a couple of
  additional command line arguments, which are generally prefixed with `rd.`

* To transition into the main system image invoke `systemctl switch-root`.

* The switch-root operation will result in a killing spree of all running
  processes. Some processes might need to be excluded from that, see the guide
  on [systemd and Storage Daemons for the Root File System](/ROOT_STORAGE_DAEMONS).
