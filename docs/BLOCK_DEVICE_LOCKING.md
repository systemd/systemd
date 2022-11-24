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

# Sample of Natively Locking The Whole Disk
The following is a basic sample to leverage `sysfs` mechanism to get the whole disk devname of a partition device and add BSD lock on the whole disk. Also see the definiton of `lock_whole_disk_from_devname` in src/shared/blockdev-util.c to know how to utilize systemd infrastructure to natively lock the whole disk from devname.

Place the code in a source file, e.g. `main.c`. Then run `gcc -o main main.c` to generate the executable `main`.

Assuming there is a partition device `/dev/sda1` in the system, run the executable with `./main /dev/sda1`. As the whole disk `/dev/sda` is not locked, the command will ouput `Successfully add lock: /dev/sda`. Run `udevadm lock -d /dev/sda sleep 10` in another terminal, the whole disk is locked for ten secs. In this duration, run `./main /dev/sda1` again, the command will give a message `Failed to add lock: Resource temporarily unavailable`.

```
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/*
 *  get_base_name
 *
 *  get the base name of 'path'
 *  e.g. 'path' is "/dev/sda", then 'ret' is "sda"
 *  e.g. 'path' is "/dev/"", then 'ret' is ""
 *
 *  restrict: 'size' is the capacity of 'ret' and should be larger than the base name
 *
 */
int get_base_name(char *path, char *ret, int size)
{
    if (path == NULL || ret == NULL){
        return -1;
    }

    int len = strlen(path);
    char *pos = strrchr(path, '/') + 1;

    if( size > ( len - ( pos - path ) + 1 )){
        snprintf(ret, len - (pos - path) + 1, "%s", pos);
        return 0;
    }else{
        return -1;
    }
}

/*
 *  get_base_dir
 *
 *  get the directory name of 'path'
 *  e.g. path is "/dev/sda", then ret is "/dev"
 *
 *  restrict: 'size' is the capacity of 'ret' and should be larger than the directory length
 *
 */
int get_base_dir(char *path, char *ret, int size)
{
    if (path == NULL || ret == NULL){
        return -1;
    }

    int len = strlen(path);
    char *pos = strrchr(path, '/') + 1;

    if( size > ( pos - path ) ){
        snprintf(ret, (pos - path), "%s", path);
        return 0;
    }else {
        return -1;
    }
}

/*
 *  is_partition
 *
 *  check whether the device is a partition by checking if there is a 'partition' file under the sysfs path
 *
 */
int is_partition(char *sysfs_path)
{
    if (sysfs_path == NULL){
        return -1;
    }

    char tmp[200] = "";
    snprintf(tmp, strlen(sysfs_path)+1, "%s", sysfs_path);
    strcat(tmp, "/partition");

    if (access(tmp, F_OK) == 0)
    {
        return 0;
    }
    else
    {
        return -1;
    }
}

/*
 *  get_whole_disk_devname
 *
 *  get the devname of the whole disk given a partition or a main block device
 *
 *  e.g. 'devname' is /dev/sda3, then 'ret' is '/dev/sda'
 *  e.g. 'devname' is /dev/sda, then 'ret' is '/dev/sda'
 *
 *  restrict: 'size' is the capacity of 'ret' and should be larger than the directory length
 *
 */
int get_whole_disk_devname(char *devname, char *ret, int size){
    if (devname == NULL || ret == NULL){
        return -1;
    }

    struct stat buffer;
    int status;
    status = stat(devname, &buffer);

    if( status < 0 || !S_ISBLK(buffer.st_mode)){
        return -1;
    }

    char base[200] = "";
    if (get_base_name(devname, base, 200) < 0){
        return -1;
    }

    // get sysfs class linkage
    char sysfs_class_block_path[200] = "";
    sprintf(sysfs_class_block_path, "/sys/class/block/");
    strcat(sysfs_class_block_path, base);

    // skip non-block device.
    if (access(sysfs_class_block_path, F_OK) != 0){
        return -1;
    }

    // get the relative path from the linkage
    char sysfs_relative_path[200] = "";
    readlink(sysfs_class_block_path, sysfs_relative_path, 200 * sizeof(char));

    // get full sysfs path
    char dir[200] = "";
    if (get_base_dir(sysfs_class_block_path, dir, 200) <0){
        return -1;
    }
    char sysDevicePath[200] = "";
    sprintf(sysDevicePath, "%s", dir);
    strcat(sysDevicePath, "/");
    strcat(sysDevicePath, sysfs_relative_path);

    // get the main block device path
    char whole_disk_devname[200] = "";
    if(is_partition(sysDevicePath) == 0){
        char parentDirectoryPath[200] = "";
        if( get_base_dir(sysDevicePath, parentDirectoryPath, 200) < 0){
            return -1;
        }

        strcat(whole_disk_devname,"/dev/");
        if(get_base_name(parentDirectoryPath, whole_disk_devname+5, 195) <0 ){
            return -1;
        }
    }else{
        strcat(whole_disk_devname, "/dev/");
        strcat(whole_disk_devname, base);
    }

    if(strlen(whole_disk_devname) < size){
        sprintf(ret,whole_disk_devname);
    }else{
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    printf("Device: %s\n", argv[1]);

    char whole_disk_devname[200] = "";
    if(get_whole_disk_devname(argv[1],whole_disk_devname,200) == 0){
        printf("Successfully get whole disk devname: %s\n", whole_disk_devname);
    }else{
        printf("Failed to whole disk devname.\n", whole_disk_devname);
        return -1;
    }

    int fd = open(whole_disk_devname, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
    int ret = flock(fd, LOCK_EX|LOCK_NB);
    if( ret <0 ){
        printf("Failed to add lock: %m\n", errno);
        return -1;
    }else{
        printf("Successfully add lock: %s\n", whole_disk_devname);
    }

    return 0;
}
```