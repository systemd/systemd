---
title: Testing systemd during Development in Virtualization
category: Documentation for Developers
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Testing systemd during Development in Virtualization

For quickly testing systemd during development it us useful to boot it up in a container and in a QEMU VM.

## Testing in a VM

Here's a nice hack if you regularly build and test-boot systemd, are gutsy enough to install it into your host, but too afraid or too lazy to continuously reboot your host.

Create a shell script like this:

```
#!/bin/sh

sudo sync
sudo /bin/sh -c 'echo 3 > /proc/sys/vm/drop_caches'
sudo umount /
sudo modprobe kvm-intel

exec sudo qemu-kvm -smp 2 -m 512 -snapshot /dev/sda
```

This will boot your local host system as a throw-away VM guest. It will take your main harddisk, boot from it in the VM, allow changes to it, but these changes are all just buffered in memory and never hit the real disk. Any changes made in this VM will be lost when the VM terminates. I have called this script "q", and hence for test booting my own system all I do is type the following command in my systemd source tree and I can see if it worked.

```
$ make -j10 && sudo make install && q

```

The first three lines are necessary to ensure that the kernel's disk caches are all synced to disk before qemu takes the snapshot of it. Yes, invoking "umount /" will sync your file system to disk as a side effect, even though it will actually fail. When the machine boots up the file system will still be marked dirty (and hence you will get an fsck, usually), but it will work fine nonetheless in virtually all cases.

Of course, if the host's hard disk changes while the VM is running this will be visible to the VM, and might confuse it. If you use this little hack you should keep changes on the host at a minimum, hence. Yeah this all is a hack, but a really useful and neat one.

YMMV if you use LVM or btrfs.

## Testing in a Container

Test-booting systemd in a container has the benefit of being much easier to debug/instrument from the outside.

**Important**: As preparation it is essential to turn off auditing entirely on your system. Auditing is broken with containers, and will trigger all kinds of error in containers if not turned off. Use `audit=0` on the host's kernel command line to turn it off.

Then, as the first step I install Fedora into a container tree:

```
$ sudo yum -y --releasever=20 --installroot=$HOME/fedora-tree --disablerepo='*' --enablerepo=fedora install systemd passwd yum fedora-release vim-minimal

```

You can do something similar with debootstrap on a Debian system. Now, we need to set a root password in order to be able to log in:

```
$ sudo systemd-nspawn -D ~/fedora-tree/
# passwd
...
# ^D
```

As the next step we can already boot the container:

```
$ sudo systemd-nspawn -bD ~/fedora-tree/ 3

```

To test systemd in the container I then run this from my source tree on the host:

```
$ make -j10 && sudo DESTDIR=$HOME/fedora-tree make install && sudo systemd-nspawn -bD ~/fedora-tree/ 3

```

And that's already it.
