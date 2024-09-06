---
title: API File Systems
category: Manuals and Documentation for Users and Administrators
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# API File Systems

_So you are seeing all kinds of weird file systems in the output of mount(8) that are not listed in `/etc/fstab`, and you wonder what those are, how you can get rid of them, or at least change their mount options._

The Linux kernel provides a number of different ways for userspace to communicate with it.
For many facilities there are system calls, others are hidden behind Netlink interfaces, and even others are exposed via virtual file systems such as `/proc` or `/sys`.
These file systems are programming interfaces, they are not actually backed by real, persistent storage.
They simply use the file system interface of the kernel as interface to various unrelated mechanisms.
Similarly, there are file systems that userspace uses for its own API purposes, to store shared memory segments, shared temporary files or sockets.
In this article we want to discuss all these kind of _API file systems_.
More specifically, here's a list of these file systems typical Linux systems currently have:

* `/sys` for exposing kernel devices, drivers and other kernel information to userspace
* `/proc` for exposing kernel settings, processes and other kernel information to userspace
* `/dev` for exposing kernel device nodes to userspace
* `/run` as location for userspace sockets and files
* `/tmp` as location for volatile, temporary userspace file system objects (X)
* `/sys/fs/cgroup` (and file systems below that) for exposing the kernel control group hierarchy
* `/sys/kernel/security`, `/sys/kernel/debug` (X), `/sys/kernel/config` (X) for exposing special purpose kernel objects to userspace
* `/sys/fs/selinux` for exposing SELinux security data to userspace
* `/dev/shm` as location for userspace shared memory objects
* `/dev/pts` for exposing kernel pseudo TTY device nodes to userspace
* `/proc/sys/fs/binfmt_misc` for registering additional binary formats in the kernel (X)
* `/dev/mqueue` for exposing mqueue IPC objects to userspace (X)
* `/dev/hugepages` as a userspace API for allocating "huge" memory pages (X)
* `/sys/fs/fuse/connections` for exposing kernel FUSE connections to userspace (X)
* `/sys/firmware/efi/efivars` for exposing firmware variables to userspace

All these _API file systems_ are mounted during very early boot-up of systemd and are generally not listed in `/etc/fstab`.
Depending on the used kernel configuration some of these API file systems might not be available and others might exist instead.
As these interfaces are important for kernel-to-userspace and userspace-to-userspace communication they are mounted automatically and without configuration or interference by the user.
Disabling or changing their parameters might hence result in applications breaking as they can no longer access the interfaces they need.

Even though the default settings of these file systems should normally be suitable for most setups, in some cases it might make sense to change the mount options, or possibly even disable some of these file systems.

Even though normally none of these API file systems are listed in `/etc/fstab` they may be added there.
If so, any options specified therein will be applied to that specific API file system.
Hence: to alter the mount options or other parameters of these file systems, simply add them to `/etc/fstab` with the appropriate settings and you are done.
Using this technique it is possible to change the source, type of a file system in addition to simply changing mount options.
That is useful to turn `/tmp` to a true file system backed by a physical disk.

It is possible to disable the automatic mounting of some (but not all) of these file systems, if that is required.
These are marked with (X) in the list above.
You may disable them simply by masking them:

```sh
systemctl mask dev-hugepages.mount
```

This has the effect that the huge memory page API FS is not mounted by default, starting with the next boot.
See [Three Levels of Off](http://0pointer.de/blog/projects/three-levels-of-off.html) for more information on masking.

The systemd service [systemd-remount-fs.service](http://www.freedesktop.org/software/systemd/man/systemd-remount-fs.service.html)
is responsible for applying mount parameters from `/etc/fstab` to the actual mounts.

## Why are you telling me all this? I just want to get rid of the tmpfs backed /tmp!

You have three options:

1. Disable any mounting on `/tmp` so that it resides on the same physical file system as the root directory.
   For that, execute `systemctl mask tmp.mount`
2. Mount a different, physical file system to `/tmp`.
   For that, simply create an entry for it in `/etc/fstab` as you would do for any other file system.
3. Keep `/tmp` but increase/decrease the size of it.
   For that, also just create an entry for it in `/etc/fstab` as you would do for any other `tmpfs` file system, and use the right `size=` option.
