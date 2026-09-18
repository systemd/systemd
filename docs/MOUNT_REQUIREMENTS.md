---
title: Mount Requirements
category: Booting
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Mount Point Availability Requirements

This document describes the requirements placed by systemd
on the time when various parts of the file system hierarchy
must be available and mounted during boot.
This document should be read in conjunction with
[UAPI.9 Linux File System Hierarchy](https://uapi-group.org/specifications/specs/linux_file_system_hierarchy/),
which describes the role of the mount points discussed here.

If the file system backing a mount point is located on external or remote media
that require special drivers, infrastructure or networking to be set up,
then this implies that this functionality must be started and running
at the point in the boot sequence when that mount point is required.

There are three general categories of mount points:

1. 🌥️ *initrd*: File system mounts that must be established before the OS
   transitions into the root file system. (I.e., must be mounted in
   the initrd before the initrd→host transition takes place.)

2. 🌤️ *early*: File system mounts that must be established
   before the end of "early boot", i.e. before `local-fs.target` is reached.
   All services that do not explicitly opt-out of the dependency
   are ordered after that point.

3. ☀️ *regular*: File system mounts that can be mounted later.
   Individual services might pull in specific mount points and be ordered after them.
   Mount points that require network to be available
   are typically ordered before `remote-fs.target`.
   Those mount points may be established as automount points.

Mounts in the later categories may be established earlier,
i.e. mounts that fall into category 2/early may also be mounted in the initrd,
and mounts in category 3/regular may also be mounted in the initrd or early boot.
Since mount points that are lower in the hierarchy are mounted later,
if a mount point is *not* split out,
but a given subtree is part of the parent mount,
the requirements for that subtree are trivially satisfied by the parent.

A "mount point" in this document means the whole subtree of the hierarchy,
until a mountpoint lower in the hierarchy which is conceptually separate.
For example, on a system with a custom mount point located below `/var/spool/`,
most of `/var/` would be in category 2/early,
but the additional mount would be in category 3/regular.
Conversely, if some part of `/usr/` that is normally part of that subtree
was split out to a separate mount,
this mount point would fall into category 1/initrd
and configuration would need to be provided for it to be mounted in the initrd.

Here's a table with relevant mounts and to which category they belong:

| *Mount*       | *Category* |
|---------------|------------|
| `/` (root fs) |  1/initrd  |
| `/usr/`       |  1/initrd  |
| `/etc/`       |  1/initrd  |
| `/var/`       |  2/early   |
| `/var/tmp/`   |  2/early   |
| `/tmp/`       |  2/early   |
| `/home/`      |  3/regular |
| `/srv/`       |  3/regular |
| XBOOTLDR      |  3/regular |
| ESP           |  3/regular |

Or in other words: the root file system (obviously…), `/usr/` and `/etc/` (if
these are split off) must be mounted at the moment the initrd transitions into
the host. Then, `/var/` (with `/var/tmp/`) and `/tmp/` (if split off) must be
mounted before the host reaches `local-fs.target` (and then `basic.target`),
after which any remaining mounts may be established.

If mounts such as `/var/` are not mounted during early boot (or from the
initrd), and require some late boot service (for example a network manager
implementation) to operate this will likely result in cyclic ordering
dependencies, and will result in various forms of boot failures.

Also note that the whole of `/var/` (including `/var/tmp/`), and `/tmp/` must
be *writable* at the moment indicated above. It's OK if they are mounted
read-only at an earlier time as long as they are remounted writable by the
indicated point in time. Systems where these three hierarchies remain read-only
during regular operation are not supported by `systemd`.

An exception to the rules described above are ephemeral systems,
where the root file system is initially an empty `tmpfs` mount point
and parts of the file system hierarchy are populated by systemd during early boot.

If you intend to use network-backed mounts (NFS, SMB, iSCSI, NVME-TCP and
similar, including anything you add the `_netdev` pseudo mount option to) for
any of the mounts from category 1/initrd or 2/early,
make sure to use a network manager that is capable of running in the initrd or early boot.
[`systemd-networkd(8)`](https://www.freedesktop.org/software/systemd/man/latest/systemd-networkd.html)
for example works well in such scenarios.

[`systemd-homed.service(8)`](https://www.freedesktop.org/software/systemd/man/latest/systemd-homed.html)
is an example of a regular service from category 3/regular.
It runs after `basic.target` and requires `/home/` to be mounted.

## Automount Points

By default, automount points are established during early boot, before `local-fs.target`,
even when the backing file system is a network file system;
only the mount unit behind them is ordered after `network-online.target`.
This is intentional:
establishing the automount point does not itself wait for the backing file system;
accesses to the path trigger mounting and wait for it to complete.

The flip side is that a network file system automounted on a path
that is accessed during early boot can hang the boot:
the accessing service blocks until the mount completes,
the mount waits for the network to come up,
and bringing up the network waits, directly or via `sysinit.target`, for the blocked service.
An automount below a network mount requires the parent network mount to be established first.
This can create an ordering cycle if the parent mount depends on networking services
ordered after `local-fs.target`.

Hence, do not use `x-systemd.automount` or automount units for network file systems
on paths from category 1/initrd,
nor on paths from category 2/early or any other path that is read by services
the network manager waits for.

`/usr/local/` is the path that bites in practice:
systemd's own services and `kmod` search `/usr/local/lib/` for configuration,
and directories under `/usr/local/` come first in the default executable search path,
so several early boot services look there whether or not anything is installed there.
Automounting `/usr/local/` from a network file system can therefore deadlock boot
if an early service accesses the active automount while the mount job waits for
a network manager ordered after that service.
This can occur with both `NetworkManager.service` and `systemd-networkd.service`,
even when connectivity was already configured in the initrd.
Like the rest of `/usr/` it falls into category 1/initrd (see above), and
[`systemd.unit(5)`](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html)
already notes that a separate `/usr/local/` partition that may be missing in early boot
must not be used for configuration.

Without an automount, incidental accesses before the network file system is mounted
see the underlying directory instead of triggering a mount and blocking.
This avoids the access-triggered deadlock described above,
but does not resolve explicit or implicit mount dependency cycles.
Anything they expect below the path is missing at that point though,
so this does not lift the requirements described above.
