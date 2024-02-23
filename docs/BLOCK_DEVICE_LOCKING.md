---
title: Locking Block Device Access
category: Interfaces
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Locking Block Device Access

*TL;DR: Use BSD file locks
[(`flock(2)`)](https://man7.org/linux/man-pages/man2/flock.2.html) on block
device nodes to synchronize access for partitioning and file system formatting
tools.*

`systemd-udevd` probes all block devices showing up for file system superblock
and partition table information (utilizing `libblkid`). If another program
concurrently modifies a superblock or partition table this probing might be
affected, which is bad in itself, but also might in turn result in undesired
effects in programs subscribing to `udev` events.

Applications manipulating a block device can temporarily stop `systemd-udevd`
from processing rules on it — and thus bar it from probing the device — by
taking a BSD file lock on the block device node. Specifically, whenever
`systemd-udevd` starts processing a block device it takes a `LOCK_SH|LOCK_NB`
lock using [`flock(2)`](https://man7.org/linux/man-pages/man2/flock.2.html) on
the main block device (i.e. never on any partition block device, but on the
device the partition belongs to). If this lock cannot be taken (i.e. `flock()`
returns `EAGAIN`), it refrains from processing the device. If it manages to take
the lock it is kept for the entire time the device is processed.

Note that `systemd-udevd` also watches all block device nodes it manages for
`inotify()` `IN_CLOSE_WRITE` events: whenever such an event is seen, this is
used as trigger to re-run the rule-set for the device.

These two concepts allow tools such as disk partitioners or file system
formatting tools to safely and easily take exclusive ownership of a block
device while operating: before starting work on the block device, they should
take an `LOCK_EX` lock on it. This has two effects: first of all, in case
`systemd-udevd` is still processing the device the tool will wait for it to
finish. Second, after the lock is taken, it can be sure that `systemd-udevd`
will refrain from processing the block device, and thus all other client
applications subscribed to it won't get device notifications from potentially
half-written data either. After the operation is complete the
partitioner/formatter can simply close the device node. This has two effects:
it implicitly releases the lock, so that `systemd-udevd` can process events on
the device node again. Secondly, it results an `IN_CLOSE_WRITE` event, which
causes `systemd-udevd` to immediately re-process the device — seeing all
changes the tool made — and notify subscribed clients about it.

Ideally, `systemd-udevd` would explicitly watch block devices for `LOCK_EX`
locks being released. Such monitoring is not supported on Linux however, which
is why it watches for `IN_CLOSE_WRITE` instead, i.e. for `close()` calls to
writable file descriptors referring to the block device. In almost all cases,
the difference between these two events does not matter much, as any locks
taken are implicitly released by `close()`. However, it should be noted that if
an application unlocks a device after completing its work without closing it,
i.e. while keeping the file descriptor open for further, longer time, then
`systemd-udevd` will not notice this and not retrigger and thus reprobe the
device.

Besides synchronizing block device access between `systemd-udevd` and such
tools this scheme may also be used to synchronize access between those tools
themselves. However, do note that `flock()` locks are advisory only. This means
if one tool honours this scheme and another tool does not, they will of course
not be synchronized properly, and might interfere with each other's work.

Note that the file locks follow the usual access semantics of BSD locks: since
`systemd-udevd` never writes to such block devices it only takes a `LOCK_SH`
*shared* lock. A program intending to make changes to the block device should
take a `LOCK_EX` *exclusive* lock instead. For further details, see the
`flock(2)` man page.

And please keep in mind: BSD file locks (`flock()`) and POSIX file locks
(`lockf()`, `F_SETLK`, …) are different concepts, and in their effect
orthogonal. The scheme discussed above uses the former and not the latter,
because these types of locks more closely match the required semantics.

If multiple devices are to be locked at the same time (for example in order to
format a RAID file system), the devices should be locked in the order of the
the device nodes' major numbers (primary ordering key, ascending) and minor
numbers (secondary ordering key, ditto), in order to avoid ABBA locking issues
between subsystems.

Note that the locks should only be taken while the device is repartitioned,
file systems formatted or `dd`'ed in, and similar cases that
apply/remove/change superblocks/partition information. It should not be held
during normal operation, i.e. while file systems on it are mounted for
application use.

The [`udevadm
lock`](https://www.freedesktop.org/software/systemd/man/udevadm.html) command
is provided to lock block devices following this scheme from the command line,
for the use in scripts and similar. (Note though that it's typically preferable
to use native support for block device locking in tools where that's
available.)

Summarizing: it is recommended to take `LOCK_EX` BSD file locks when
manipulating block devices in all tools that change file system block devices
(`mkfs`, `fsck`, …) or partition tables (`fdisk`, `parted`, …), right after
opening the node.

# Example of Locking The Whole Disk

The following is an example to leverage `libsystemd` infrastructure to get the whole disk of a block device and take a BSD lock on it.

## Compile and Execute
**Note that this example requires `libsystemd` version 251 or newer.**

Place the code in a source file, e.g. `take_BSD_lock.c` and run the following commands:
```
$ gcc -o take_BSD_lock -lsystemd take_BSD_lock.c

$ ./take_BSD_lock /dev/sda1
Successfully took a BSD lock: /dev/sda

$ flock -x /dev/sda ./take_BSD_lock /dev/sda1
Failed to take a BSD lock on /dev/sda: Resource temporarily unavailable
```

## Code
```c
/* SPDX-License-Identifier: MIT-0 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <systemd/sd-device.h>
#include <unistd.h>

static inline void closep(int *fd) {
    if (*fd >= 0)
        close(*fd);
}

/**
 * lock_whole_disk_from_devname
 * @devname: devname of a block device, e.g., /dev/sda or /dev/sda1
 * @open_flags: the flags to open the device, e.g., O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY
 * @flock_operation: the operation to call flock, e.g., LOCK_EX|LOCK_NB
 *
 * given the devname of a block device, take a BSD lock of the whole disk
 *
 * Returns: negative errno value on error, or non-negative fd if the lock was taken successfully.
 **/
int lock_whole_disk_from_devname(const char *devname, int open_flags, int flock_operation) {
    __attribute__((cleanup(sd_device_unrefp))) sd_device *dev = NULL;
    sd_device *whole_dev;
    const char *whole_disk_devname, *subsystem, *devtype;
    int r;

    // create a sd_device instance from devname
    r = sd_device_new_from_devname(&dev, devname);
    if (r < 0) {
        errno = -r;
        fprintf(stderr, "Failed to create sd_device: %m\n");
        return r;
    }

    // if the subsystem of dev is block, but its devtype is not disk, find its parent
    r = sd_device_get_subsystem(dev, &subsystem);
    if (r < 0) {
        errno = -r;
        fprintf(stderr, "Failed to get the subsystem: %m\n");
        return r;
    }
    if (strcmp(subsystem, "block") != 0) {
        fprintf(stderr, "%s is not a block device, refusing.\n", devname);
        return -EINVAL;
    }

    r = sd_device_get_devtype(dev, &devtype);
    if (r < 0) {
        errno = -r;
        fprintf(stderr, "Failed to get the devtype: %m\n");
        return r;
    }
    if (strcmp(devtype, "disk") == 0)
        whole_dev = dev;
    else {
        r = sd_device_get_parent_with_subsystem_devtype(dev, "block", "disk", &whole_dev);
        if (r < 0) {
            errno = -r;
            fprintf(stderr, "Failed to get the parent device: %m\n");
            return r;
        }
    }

    // open the whole disk device node
    __attribute__((cleanup(closep))) int fd = sd_device_open(whole_dev, open_flags);
    if (fd < 0) {
        errno = -fd;
        fprintf(stderr, "Failed to open the device: %m\n");
        return fd;
    }

    // get the whole disk devname
    r = sd_device_get_devname(whole_dev, &whole_disk_devname);
    if (r < 0) {
        errno = -r;
        fprintf(stderr, "Failed to get the whole disk name: %m\n");
        return r;
    }

    // take a BSD lock of the whole disk device node
    if (flock(fd, flock_operation) < 0) {
        r = -errno;
        fprintf(stderr, "Failed to take a BSD lock on %s: %m\n", whole_disk_devname);
        return r;
    }

    printf("Successfully took a BSD lock: %s\n", whole_disk_devname);

    // take the fd to avoid automatic cleanup
    int ret_fd = fd;
    fd = -EBADF;
    return ret_fd;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Invalid number of parameters.\n");
        return EXIT_FAILURE;
    }

    // try to take an exclusive and nonblocking BSD lock
    __attribute__((cleanup(closep))) int fd =
        lock_whole_disk_from_devname(
            argv[1],
            O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY,
            LOCK_EX|LOCK_NB);

    if (fd < 0)
        return EXIT_FAILURE;

    /**
     * The device is now locked until the return below.
     * Now you can safely manipulate the block device.
     **/

    return EXIT_SUCCESS;
}
```
