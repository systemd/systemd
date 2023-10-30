---
title: Mount Requirements
category: Booting
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Mount Point Availability Requirements

systemd makes various requirements on the time during boot where various parts
of the Linux file system hierarchy must be available and must be mounted. If
the file systems backing these mounts are located on external or remote media,
that require special drivers, infrastructure or networking to be set up, then
this implies that this functionality must be started and running at that point
already.

Generally, there are three categories of requirements:

1. 🌥️ *initrd*: File system mounts that must be established before the OS
   transitions into the root file system. (i.e. that must be stablished from
   the initrd before the initrd→host transition takes place.)

2. 🌤️ *early*: File system mounts that must be established during early boot,
   after the initrd→host transition took place, but before regular services are
   started. (i.e. before `local-fs.target` is reached.)

3. ☀️ *regular*: File system mounts that can be mounted at any time during the
   boot process – but which specific, individual services might require to be
   established at the point they are started. (i.e. these mounts are typically
   ordered before `remote-fs.target`.)

Of course, mounts that fall into category 3 can also be mounted during the
initrd or in early boot. And those from category 2 can also be mounted already
from the initrd.

Here's a table with relevant mounts and to which category they belong:

| *Mount*       | *Category* |
|---------------|------------|
| `/` (root fs) |          1 |
| `/usr/`       |          1 |
| `/etc/`       |          1 |
| `/var/`       |          2 |
| `/var/tmp/`   |          2 |
| `/tmp/`       |          2 |
| `/home/`      |          3 |
| `/srv/`       |          3 |
| XBOOTLDR      |          3 |
| ESP           |          3 |

Or in other words: the root file system (obviously…), `/usr/` and `/etc/` (if
these are split off) must be mounted at the moment the initrd transitions into
the host. Then, `/var/` (with `/var/tmp/`) and `/tmp/` (if split off) must be
mounted, before the host reaches `local-fs.target` (and then `basic.target`),
after which any remaining mounts may be established.

If mounts such as `/var/` are not mounted during early boot (or from the
initrd), and require some late boot service (for example a network manager
implementation) to operate this will likely result in cyclic ordering
dependencies, and will result in various forms of boot failures.

If you intend to use network-backed mounts (NFS, SMB, iSCSI, NVME-TCP and
similar, including anything you add the `_netdev` pseudo mount option to) for
any of the mounts from category 1 or 2, make sure to use a network managing
implementation that is capable of running from the initrd/during early
boot. [`systemd-networkd(8)`](https://www.freedesktop.org/software/systemd/man/latest/systemd-networkd.html)
for example works well in such scenarios.

Note that
[`systemd-homed.service(8)`](https://www.freedesktop.org/software/systemd/man/latest/systemd-homed.html)
(which is a regular service, i.e. runs after `basic.target`) requires `/home/`
to be mounted.
