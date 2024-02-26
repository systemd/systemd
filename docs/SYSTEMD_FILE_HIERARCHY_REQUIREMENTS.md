---
title: systemd File Hierarchy Requirements
category: Documentation for Developers
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# systemd File Hierarchy Requirements

There are various attempts to standardize the file system hierarchy of Linux systems.
In systemd we leave much of the file system layout open to the operating system, but here's what systemd strictly requires:

- `/`, `/usr`, `/etc` must be mounted when the host systemd is first invoked.
  This may be achieved either by using the kernel's built-in root disk mounting (in which case `/`, `/usr` and `/etc` need to be on the same file system), or via an initrd, which could mount the three directories from different sources.

- `/bin`, `/sbin`, `/lib` (and `/lib64` if applicable) should reside on `/`, or be symlinks to the `/usr` file system (recommended).
  All of them must be available before the host systemd is first executed.

- `/var` does not have to be mounted when the host systemd is first invoked, however,
  it must be configured so that it is mounted writable before local-fs.target is reached (for example, by simply listing it in` /etc/fstab`).

- `/tmp` is recommended to be a tmpfs (default), but doesn't have to.
  If configured, it must be mounted before local-fs.target is reached (for example, by listing it in `/etc/fstab`).

- `/dev` must exist as an empty mount point and will automatically be mounted by systemd with a devtmpfs. Non-devtmpfs boots are not supported.

- `/proc` and `/sys` must exist as empty mount points and will automatically be mounted by systemd with procfs and sysfs.

- `/run` must exist as an empty mount point and will automatically be mounted by systemd with a tmpfs.

The other directories usually found in the root directory (such as `/home`, `/boot`, `/opt`) are irrelevant to systemd.
If they are defined they may be mounted from any source and at any time, though it is a good idea to mount them also before local-fs.target is reached.
