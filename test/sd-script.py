#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# sd-script.py: create LOTS of sd device entries in fake sysfs
#
# (C) 2018 Martin Wilck, SUSE Linux GmbH
#
# Run after sys-script.py
# Usage: sd-script.py <directory> <num>
# <num> is the number of device nodes (disks + partitions)
# to create in addition to what sys-script.py already did.
# The script can be run several times in a row if <num> is increased,
# adding yet more device entries.
# Tested up to 1000 entries, more are possible.
# Note that sys-script.py already creates 10 sd device nodes
# (sda+sdb and partitions). This script starts with sdc.

import re
import os
import errno
import sys

def d(path, mode):
    os.mkdir(path, mode)

def l(path, src):
    os.symlink(src, path)

def f(path, mode, contents):
    with open(path, "wb") as f:
        f.write(contents)
    os.chmod(path, mode)

class SD(object):

    sd_major = [8] + list(range(65, 72)) + list(range(128, 136))
    _name_re = re.compile(r'sd(?P<f>[a-z]*)$')

    def _init_from_name(self, name):
        mt = self._name_re.match(name)
        if mt is None:
            raise RuntimeError("invalid name %s" % name)
        nm = mt.group("f")
        base = 1
        ls = nm[-1]
        nm = nm[:-1]
        n = base * (ord(ls)-ord('a'))
        while len(nm) > 0:
            ls = nm[-1]
            nm = nm[:-1]
            base *= 26
            n += base * (1 + ord(ls)-ord('a'))
        self._num = n

    def _init_from_dev(self, dev):
        maj, min = dev.split(":")
        maj = self.sd_major.index(int(maj, 10))
        min = int(min, 10)
        num = int(min / 16)
        self._num = 16*maj + num%16 + 256*int(num/16)

    @staticmethod
    def _disk_num(a, b):
        n = ord(a)-ord('a')
        if b != '':
            n = 26 * (n+1) + ord(b)-ord('a')
        return n

    @staticmethod
    def _get_major(n):
        return SD.sd_major[(n%256)//16]
    @staticmethod
    def _get_minor(n):
        return 16 * (n % 16 + 16 * n//256)

    @staticmethod
    def _get_name(n):
        # see sd_format_disk_name() (sd.c)
        s = chr(n % 26 + ord('a'))
        n = n // 26 - 1
        while n >= 0:
            s = chr(n % 26 + ord('a')) + s
            n = n // 26 - 1
        return "sd" + s

    @staticmethod
    def _get_dev_t(n):
        maj = SD._get_major(n)
        min = SD._get_minor(n)
        return (maj << 20) + min

    def __init__(self, arg):
        if type(arg) is type(0):
            self._num = arg
        elif arg.startswith("sd"):
            self._init_from_name(arg)
        else:
            self._init_from_dev(arg)

    def __cmp__(self, other):
        return cmp(self._num, other._num)

    def __eq__(self, other):
        return self.__cmp__(other) == 0

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self._num)

    def __str__(self):
        return "%s/%s" % (
            self.devstr(),
            self._get_name(self._num))

    def major(self):
        return self._get_major(self._num)

    def minor(self):
        return self._get_minor(self._num)

    def devstr(self):
        return "%d:%d" % (self._get_major(self._num),
                          self._get_minor(self._num))

    def namestr(self):
        return self._get_name(self._num)

    def longstr(self):
        return "%d\t%s\t%s\t%08x" % (self._num,
                                     self.devstr(),
                                     self.namestr(),
                                     self._get_dev_t(self._num))

class MySD(SD):
    def subst(self, first_sg):
        disk = {
            "lun": self._num,
            "major": self.major(),
            "devnode": self.namestr(),
            "disk_minor": self.minor(),
            "sg_minor": first_sg + self._num,
        }
        return disk

disk_template = r"""\
l('sys/bus/scsi/drivers/sd/7:0:0:{lun}', '../../../../devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}')
l('sys/bus/scsi/devices/7:0:0:{lun}', '../../../devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}')
l('sys/dev/char/254:{sg_minor}', '../../devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/bsg/7:0:0:{lun}')
l('sys/dev/char/21:{sg_minor}', '../../devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/scsi_generic/sg{sg_minor}')
l('sys/class/scsi_disk/7:0:0:{lun}', '../../devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/scsi_disk/7:0:0:{lun}')
l('sys/class/scsi_generic/sg{sg_minor}', '../../devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/scsi_generic/sg{sg_minor}')
l('sys/class/bsg/7:0:0:{lun}', '../../devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/bsg/7:0:0:{lun}')
l('sys/class/scsi_device/7:0:0:{lun}', '../../devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/scsi_device/7:0:0:{lun}')
d('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}', 0o755)
l('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/generic', 'scsi_generic/sg{sg_minor}')
l('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/subsystem', '../../../../../../../../../bus/scsi')
l('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/driver', '../../../../../../../../../bus/scsi/drivers/sd')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/iodone_cnt', 0o644, b'0xc3\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/device_blocked', 0o644, b'0\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/max_sectors', 0o644, b'240\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/modalias', 0o644, b'scsi:t-0x00\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/scsi_level', 0o644, b'3\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/queue_depth', 0o644, b'1\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/rev', 0o644, b'1.00\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/type', 0o644, b'0\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/iocounterbits', 0o644, b'32\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/vendor', 0o644, b'Generic \n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/state', 0o644, b'running\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/queue_type', 0o644, b'none\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/iorequest_cnt', 0o644, b'0xc3\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/evt_media_change', 0o644, b'0\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/model', 0o644, b'USB Flash Drive \n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/ioerr_cnt', 0o644, b'0x2\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/uevent', 0o644, b'''DEVTYPE=scsi_device
DRIVER=sd
MODALIAS=scsi:t-0x00
''')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/timeout', 0o644, b'60\n')
d('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/scsi_disk', 0o755)
d('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/scsi_disk/7:0:0:{lun}', 0o755)
l('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/scsi_disk/7:0:0:{lun}/subsystem', '../../../../../../../../../../../class/scsi_disk')
l('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/scsi_disk/7:0:0:{lun}/device', '../../../7:0:0:{lun}')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/scsi_disk/7:0:0:{lun}/app_tag_own', 0o644, b'0\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/scsi_disk/7:0:0:{lun}/FUA', 0o644, b'0\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/scsi_disk/7:0:0:{lun}/cache_type', 0o644, b'write through\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/scsi_disk/7:0:0:{lun}/protection_type', 0o644, b'0\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/scsi_disk/7:0:0:{lun}/manage_start_stop', 0o644, b'0\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/scsi_disk/7:0:0:{lun}/allow_restart', 0o644, b'1\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/scsi_disk/7:0:0:{lun}/uevent', 0o644, b'')
d('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/scsi_disk/7:0:0:{lun}/power', 0o755)
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/scsi_disk/7:0:0:{lun}/power/wakeup', 0o644, b'\n')
d('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/power', 0o755)
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/power/wakeup', 0o644, b'\n')
d('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/scsi_generic', 0o755)
d('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/scsi_generic/sg{sg_minor}', 0o755)
l('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/scsi_generic/sg{sg_minor}/subsystem', '../../../../../../../../../../../class/scsi_generic')
l('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/scsi_generic/sg{sg_minor}/device', '../../../7:0:0:{lun}')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/scsi_generic/sg{sg_minor}/dev', 0o644, b'21:{sg_minor}\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/scsi_generic/sg{sg_minor}/uevent', 0o644, b'''MAJOR=21
MINOR={sg_minor}
''')
d('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/scsi_generic/sg{sg_minor}/power', 0o755)
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/scsi_generic/sg{sg_minor}/power/wakeup', 0o644, b'\n')
d('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/bsg', 0o755)
d('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/bsg/7:0:0:{lun}', 0o755)
l('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/bsg/7:0:0:{lun}/subsystem', '../../../../../../../../../../../class/bsg')
l('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/bsg/7:0:0:{lun}/device', '../../../7:0:0:{lun}')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/bsg/7:0:0:{lun}/dev', 0o644, b'254:{sg_minor}\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/bsg/7:0:0:{lun}/uevent', 0o644, b'''MAJOR=254
MINOR={sg_minor}
''')
d('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/bsg/7:0:0:{lun}/power', 0o755)
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/bsg/7:0:0:{lun}/power/wakeup', 0o644, b'\n')
d('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block', 0o755)
d('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/scsi_device', 0o755)
d('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/scsi_device/7:0:0:{lun}', 0o755)
l('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/scsi_device/7:0:0:{lun}/subsystem', '../../../../../../../../../../../class/scsi_device')
l('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/scsi_device/7:0:0:{lun}/device', '../../../7:0:0:{lun}')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/scsi_device/7:0:0:{lun}/uevent', 0o644, b'')
d('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/scsi_device/7:0:0:{lun}/power', 0o755)
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/scsi_device/7:0:0:{lun}/power/wakeup', 0o644, b'\n')
l('sys/dev/block/{major}:{disk_minor}', '../../devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}')
l('sys/class/block/{devnode}', '../../devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}')
l('sys/block/{devnode}', '../devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}')
d('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}', 0o755)
l('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/subsystem', '../../../../../../../../../../../class/block')
l('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/bdi', '../../../../../../../../../../virtual/bdi/{major}:{disk_minor}')
l('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/device', '../../../7:0:0:{lun}')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/capability', 0o644, b'13\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/ro', 0o644, b'0\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/make-it-fail', 0o644, b'0\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/size', 0o644, b'257024\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/dev', 0o644, b'{major}:{disk_minor}\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/range', 0o644, b'16\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/removable', 0o644, b'1\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/stat', 0o644, b'     117      409     2103      272        0        0        0        0        0      194      272\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/uevent', 0o644, b'''MAJOR={major}
MINOR={disk_minor}
DEVTYPE=disk
DEVNAME={devnode}
''')
d('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/queue', 0o755)
l('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/queue/bsg', '../../../bsg/7:0:0:{lun}')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/queue/nr_requests', 0o644, b'128\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/queue/nomerges', 0o644, b'0\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/queue/scheduler', 0o644, b'noop anticipatory deadline [cfq] \n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/queue/hw_sector_size', 0o644, b'512\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/queue/max_hw_sectors_kb', 0o644, b'120\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/queue/read_ahead_kb', 0o644, b'128\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/queue/max_sectors_kb', 0o644, b'120\n')
d('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/queue/iosched', 0o755)
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/queue/iosched/slice_async_rq', 0o644, b'2\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/queue/iosched/back_seek_max', 0o644, b'16384\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/queue/iosched/slice_sync', 0o644, b'100\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/queue/iosched/slice_async', 0o644, b'40\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/queue/iosched/fifo_expire_sync', 0o644, b'125\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/queue/iosched/slice_idle', 0o644, b'8\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/queue/iosched/back_seek_penalty', 0o644, b'2\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/queue/iosched/fifo_expire_async', 0o644, b'250\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/queue/iosched/quantum', 0o644, b'4\n')
d('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/power', 0o755)
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/power/wakeup', 0o644, b'\n')
"""

part_template = r"""\
l('sys/dev/block/{major}:{part_minor}', '../../devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/{devnode}{part_num}')
l('sys/class/block/{devnode}{part_num}', '../../devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/{devnode}{part_num}')
d('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/{devnode}{part_num}', 0o755)
l('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/{devnode}{part_num}/subsystem', '../../../../../../../../../../../../class/block')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/{devnode}{part_num}/start', 0o644, b'32\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/{devnode}{part_num}/make-it-fail', 0o644, b'0\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/{devnode}{part_num}/size', 0o644, b'256992\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/{devnode}{part_num}/dev', 0o644, b'{major}:{part_minor}\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/{devnode}{part_num}/stat', 0o644, b'     109      392     1903      246        0        0        0        0        0      169      246\n')
f('sys/devices/pci0000:00/0000:00:1d.7/usb5/5-1/5-1:1.0/host7/target7:0:0/7:0:0:{lun}/block/{devnode}/{devnode}{part_num}/uevent', 0o644, b'''MAJOR={major}
MINOR={part_minor}
DEVTYPE=partition
DEVNAME={devnode}{part_num}
''')
"""

if len(sys.argv) != 3:
    exit("Usage: {} <target dir> <number>".format(sys.argv[0]))

if not os.path.isdir(sys.argv[1]):
    exit("Target dir {} not found".format(sys.argv[1]))

def create_part_sysfs(disk, sd, prt):
    part = disk
    part.update ({
        "part_num": prt,
        "part_minor": disk["disk_minor"] + prt,
    })

    try:
        exec(part_template.format(**part))
    except OSError:
        si = sys.exc_info()[1]
        if (si.errno == errno.EEXIST):
            print("sysfs structures for %s%d exist" % (sd.namestr(), prt))
        else:
            print("error for %s%d: %s" % (sd.namestr(), prt, si[1]))
            raise
    else:
        print("sysfs structures for %s%d created" % (sd.namestr(), prt))

def create_disk_sysfs(dsk, first_sg, n):
    sd = MySD(dsk)
    disk = sd.subst(first_sg)

    try:
        exec(disk_template.format(**disk))
    except OSError:
        si = sys.exc_info()[1]
        if (si.errno == errno.EEXIST):
            print("sysfs structures for %s exist" % sd.namestr())
        elif (si.errno == errno.ENOENT):
            print("error for %s: %s - have you run sys-script py first?" %
                  (sd.namestr(), si.strerror))
            return -1
        else:
            print("error for %s: %s" % (sd.namestr(), si.strerror))
            raise
    else:
        print("sysfs structures for %s created" % sd.namestr())

    n += 1
    if n >= last:
        return n

    for prt in range(1, 16):
        create_part_sysfs(disk, sd, prt)
        n += 1
        if n >= last:
            return n

    return n

os.chdir(sys.argv[1])
n = 0
last = int(sys.argv[2])
first_sg = 2
for dsk in range(2, 1000):
    n = create_disk_sysfs(dsk, first_sg, n)
    if n >= last or n == -1:
        break
