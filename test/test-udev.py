#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

# pylint: disable=redefined-outer-name,no-else-return,multiple-imports
# pylint: disable=consider-using-with,global-statement

# udev test
#
# Provides automated testing of the udev binary.
# The whole test is self contained in this file, except the matching sysfs tree.
# Simply extend RULES to add a new test.
#
# Every test is driven by its own temporary config file.
# This program prepares the environment, creates the config and calls udev.
#
# udev parses the rules, looks at the provided sysfs and first creates and then
# removes the device node. After creation and removal the result is checked
# against the expected value and the result is printed.

import dataclasses
import functools
import os
import pwd, grp
import re
import stat
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path
from typing import Callable, Optional

try:
    import pytest
except ImportError as e:
    print(str(e), file=sys.stderr)
    sys.exit(77)


SYS_SCRIPT     = Path(__file__).with_name('sys-script.py')
try:
    UDEV_BIN   = Path(os.environ['UDEV_RULE_RUNNER'])
except KeyError:
    UDEV_BIN   = Path(__file__).parent / 'manual/test-udev-rule-runner'
UDEV_BIN = UDEV_BIN.absolute()

# Those will be set by the udev_setup() fixture
UDEV_RUN = UDEV_RULES = UDEV_DEV = UDEV_SYS = None

# Relax sd-device's sysfs verification, since we want to provide a fake sysfs
# here that actually is a tmpfs.
os.environ['SYSTEMD_DEVICE_VERIFY_SYSFS'] = '0'

rules_10k_tags = \
    '\n'.join(f'KERNEL=="sda", TAG+="test{i + 1}"'
              for i in range(10_000))

rules_10k_tags_continuation = \
    ',\\\n'.join(('KERNEL=="sda"',
                  *(f'TAG+="test{i + 1}"' for i in range(10_000))))

@dataclasses.dataclass
class Device:
    devpath: str
    devnode: Optional[str] = None
    exp_links: Optional[list[str]] = None
    not_exp_links: Optional[list[str]] = None

    exp_perms: Optional[int] = None
    exp_major_minor: Optional[str] = None

    def check_permissions(self, st: os.stat_result) -> None:
        if self.exp_perms is None:
            return

        user, group, mode = self.exp_perms.split(':')

        if user:
            try:
                uid = pwd.getpwnam(user).pw_uid
            except KeyError:
                uid = int(user)
            assert uid == st.st_uid

        if group:
            try:
                gid = grp.getgrnam(group).gr_gid
            except KeyError:
                gid = int(group)
            assert gid == st.st_gid

        if mode:
            mode = int(mode, 8)
            assert stat.S_IMODE(st.st_mode) == mode

    def check_major_minor(self, st: os.stat_result) -> None:
        if not self.exp_major_minor:
            return
        minor, major = (int(x) for x in self.exp_major_minor.split(':'))
        assert st.st_rdev == os.makedev(minor, major)

    def get_devnode(self) -> Path:
        suffix = self.devnode if self.devnode else self.devpath.split('/')[-1]
        return UDEV_DEV / suffix

    def check_link_add(self, link: str, devnode: Path) -> None:
        link = UDEV_DEV / link
        tgt = link.parent / link.readlink()
        assert devnode.samefile(tgt)

    def check_link_nonexistent(self, link: str, devnode: Path) -> None:
        link = UDEV_DEV / link

        try:
            tgt = link.parent / link.readlink()
        except FileNotFoundError:
            return

        assert not devnode.samefile(tgt)

    def check_add(self) -> None:
        print(f'check_add {self.devpath}')

        devnode = self.get_devnode()
        st = devnode.lstat()
        assert stat.S_ISCHR(st.st_mode) or stat.S_ISBLK(st.st_mode)
        self.check_permissions(st)
        self.check_major_minor(st)

        for link in self.exp_links or []:
            self.check_link_add(link, devnode)

        for link in self.not_exp_links or []:
            self.check_link_nonexistent(link, devnode)

    def check_link_remove(self, link: str) -> None:
        link = UDEV_DEV / link
        with pytest.raises(FileNotFoundError):
            link.readlink()

    def check_remove(self) -> None:
        devnode = self.get_devnode()
        assert not devnode.exists()

        for link in self.exp_links or []:
            self.check_link_remove(link)


def listify(f):
    def wrap(*args, **kwargs):
        return list(f(*args, **kwargs))
    return functools.update_wrapper(wrap, f)

@listify
def all_block_devs(exp_func) -> list[Device]:
    # Create a device list with all block devices under /sys
    # (except virtual devices and cd-roms)
    # the optional argument exp_func returns expected and non-expected
    # symlinks for the device.

    for p in UDEV_SYS.glob('dev/block/*'):
        tgt = os.readlink(p)
        if re.search('/virtual/ | /sr[0-9]*$', tgt, re.VERBOSE):
            continue

        assert tgt.startswith('../../')
        tgt = tgt[5:]

        exp, not_exp = exp_func(tgt)
        yield Device(devpath=tgt,
                     exp_links=exp,
                     not_exp_links=not_exp)


@dataclasses.dataclass
class Rules:
    desc: str
    devices: list[Device]
    rules: str
    device_generator: Callable = None
    repeat: int = 1
    delay: Optional[int] = None

    @classmethod
    def new(cls, desc: str, *devices, rules=None, device_generator=None, **kwargs):
        assert rules.startswith('\n')
        rules = textwrap.dedent(rules[1:]) if rules else ''

        assert bool(devices) ^ bool(device_generator)

        return cls(desc, devices, rules, device_generator=device_generator, **kwargs)

    def generate_devices(self) -> None:
        # We can't do this when the class is created, because setup is done later.
        if self.device_generator:
            self.devices = self.device_generator()

    def create_rules_file(self) -> None:
        # create temporary rules
        UDEV_RULES.parent.mkdir(exist_ok=True, parents=True)
        UDEV_RULES.write_text(self.rules)

RULES = [
    Rules.new(
        'no rules',
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
        ),
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
        ),
        rules = r"""
        #
        """),

    Rules.new(
        'label test of scsi disc',
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links = ["boot_disk"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", SYMLINK+="boot_disk%n"
        KERNEL=="ttyACM0", SYMLINK+="modem"
        """),

    Rules.new(
        "label test of scsi disc",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links = ["boot_disk"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", SYMLINK+="boot_disk%n"
        KERNEL=="ttyACM0", SYMLINK+="modem"
        """),

    Rules.new(
        "label test of scsi disc",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links = ["boot_disk"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", SYMLINK+="boot_disk%n"
        KERNEL=="ttyACM0", SYMLINK+="modem"
        """),

    Rules.new(
        "label test of scsi partition",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
            exp_links = ["boot_disk1"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", SYMLINK+="boot_disk%n"
        """),

    Rules.new(
        "label test of pattern match",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
            exp_links     = ["boot_disk1", "boot_disk1-4", "boot_disk1-5"],
            not_exp_links = ["boot_disk1-1", "boot_disk1-2", "boot_disk1-3", "boot_disk1-6", "boot_disk1-7"],
        ),

        rules = r"""
        SUBSYSTEMS=="scsi", ATTRS{vendor}=="?ATA", SYMLINK+="boot_disk%n-1"
        SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA?", SYMLINK+="boot_disk%n-2"
        SUBSYSTEMS=="scsi", ATTRS{vendor}=="A??", SYMLINK+="boot_disk%n"
        SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATAS", SYMLINK+="boot_disk%n-3"
        SUBSYSTEMS=="scsi", ATTRS{vendor}=="AT?", SYMLINK+="boot_disk%n-4"
        SUBSYSTEMS=="scsi", ATTRS{vendor}=="??A", SYMLINK+="boot_disk%n-5"
        SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", GOTO="skip-6"
        SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", SYMLINK+="boot_disk%n-6"
        LABEL="skip-6"
        SUBSYSTEMS=="scsi", GOTO="skip-7"
        SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", SYMLINK+="boot_disk%n-7"
        LABEL="skip-7"
        """),

    Rules.new(
        "label test of multiple sysfs files",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
            exp_links       = ["boot_disk1"],
            not_exp_links   = ["boot_diskX1"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", ATTRS{model}=="ST910021AS X ", SYMLINK+="boot_diskX%n"
        SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", ATTRS{model}=="ST910021AS", SYMLINK+="boot_disk%n"
        """),

    Rules.new(
        "label test of max sysfs files (skip invalid rule)",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
            exp_links       = ["boot_disk1", "boot_diskXY1"],
            not_exp_links   = ["boot_diskXX1"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", ATTRS{model}=="ST910021AS", ATTRS{scsi_level}=="6", ATTRS{rev}=="4.06", ATTRS{type}=="0", ATTRS{queue_depth}=="32", SYMLINK+="boot_diskXX%n"
        SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", ATTRS{model}=="ST910021AS", ATTRS{scsi_level}=="6", ATTRS{rev}=="4.06", ATTRS{type}=="0", ATTRS{queue_depth}=="1", SYMLINK+="boot_diskXY%n"
        SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", ATTRS{model}=="ST910021AS", ATTRS{scsi_level}=="6", ATTRS{rev}=="4.06", ATTRS{type}=="0", SYMLINK+="boot_disk%n"
        """),

    Rules.new(
        "SYMLINK tests",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
            exp_links       = ["link1", "link2/foo", "link3/aaa/bbb",
                               "abs1", "abs2/foo", "abs3/aaa/bbb",
                               "default___replace_test/foo_aaa",
                               "string_escape___replace/foo_bbb",
                               "env_with_space",
                               "default/replace/mode_foo__hoge",
                               "replace_env_harder_foo__hoge",
                               "match", "unmatch"],
            not_exp_links   = ["removed1", "removed2", "removed3", "unsafe/../../path", "/nondev/path/will/be/refused"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", ATTRS{model}=="ST910021AS", SYMLINK+="removed1"
        SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", ATTRS{model}=="ST910021AS", SYMLINK-="removed1"
        SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", ATTRS{model}=="ST910021AS", SYMLINK+="/./dev///removed2"
        SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", ATTRS{model}=="ST910021AS", SYMLINK-="removed2"
        SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", ATTRS{model}=="ST910021AS", SYMLINK+="././removed3"
        SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", ATTRS{model}=="ST910021AS", SYMLINK-="/dev//./removed3/./"
        SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", ATTRS{model}=="ST910021AS", SYMLINK+="unsafe/../../path"
        SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", ATTRS{model}=="ST910021AS", SYMLINK+="/nondev/path/will/be/refused"
        SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", ATTRS{model}=="ST910021AS", SYMLINK+="link1 .///link2/././/foo//./ .///link3/aaa/bbb"
        SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", ATTRS{model}=="ST910021AS", SYMLINK+="/dev/abs1 /dev//./abs2///foo/./ ////dev/abs3/aaa/bbb"
        SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", ATTRS{model}=="ST910021AS", SYMLINK+="default?;;replace%%test/foo'aaa"
        SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", ATTRS{model}=="ST910021AS", OPTIONS="string_escape=replace", SYMLINK+="string_escape   replace/foo%%bbb"
        SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", ATTRS{model}=="ST910021AS", ENV{.HOGE}="env    with    space", SYMLINK+="%E{.HOGE}"
        SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", ATTRS{model}=="ST910021AS", ENV{.HOGE}="default/replace/mode?foo;;hoge", SYMLINK+="%E{.HOGE}"
        SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", ATTRS{model}=="ST910021AS", OPTIONS="string_escape=replace", ENV{.HOGE}="replace/env/harder?foo;;hoge", SYMLINK+="%E{.HOGE}"
        SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", ATTRS{model}=="ST910021AS", SYMLINK=="link1", SYMLINK+="match"
        SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", ATTRS{model}=="ST910021AS", SYMLINK!="removed1", SYMLINK+="unmatch"
        """),

    Rules.new(
        "catch device by *",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_links       = ["modem/0", "catch-all"],
        ),
        rules = r"""
        KERNEL=="ttyACM*", SYMLINK+="modem/%n"
        KERNEL=="*", SYMLINK+="catch-all"
        """),

    Rules.new(
        "catch device by * - take 2",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_links       = ["modem/0"],
            not_exp_links   = ["bad"],
        ),
        rules = r"""
        KERNEL=="*ACM1", SYMLINK+="bad"
        KERNEL=="*ACM0", SYMLINK+="modem/%n"
        """),

    Rules.new(
        "catch device by ?",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_links       = ["modem/0"],
            not_exp_links   = ["modem/0-1", "modem/0-2"],
        ),
        rules = r"""
        KERNEL=="ttyACM??*", SYMLINK+="modem/%n-1"
        KERNEL=="ttyACM??", SYMLINK+="modem/%n-2"
        KERNEL=="ttyACM?", SYMLINK+="modem/%n"
        """),

    Rules.new(
        "catch device by character class",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_links       = ["modem/0"],
            not_exp_links   = ["modem/0-1", "modem/0-2"],
        ),
        rules = r"""
        KERNEL=="ttyACM[A-Z]*", SYMLINK+="modem/%n-1"
        KERNEL=="ttyACM?[0-9]", SYMLINK+="modem/%n-2"
        KERNEL=="ttyACM[0-9]*", SYMLINK+="modem/%n"
        """),

    Rules.new(
        "don't replace kernel name",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_links       = ["modem"],
        ),
        rules = r"""
        KERNEL=="ttyACM0", SYMLINK+="modem"
        """),

    Rules.new(
        "comment lines in config file (and don't replace kernel name)",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_links       = ["modem"],
        ),
        rules = r"""
        # this is a comment
        KERNEL=="ttyACM0", SYMLINK+="modem"

        """),

    Rules.new(
        "comment lines in config file with whitespace (and don't replace kernel name)",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_links       = ["modem"],
        ),
        rules = r"""
         # this is a comment with whitespace before the comment
        KERNEL=="ttyACM0", SYMLINK+="modem"

        """),

    Rules.new(
        "whitespace only lines (and don't replace kernel name)",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_links       = ["whitespace"],
        ),
        rules = r"""



         # this is a comment with whitespace before the comment
        KERNEL=="ttyACM0", SYMLINK+="whitespace"



        """),

    Rules.new(
        "empty lines in config file (and don't replace kernel name)",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_links       = ["modem"],
        ),
        rules = r"""

        KERNEL=="ttyACM0", SYMLINK+="modem"

        """),

    Rules.new(
        "backslashed multi lines in config file (and don't replace kernel name)",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_links       = ["modem"],
        ),
        rules = r"""
        KERNEL=="ttyACM0", \
        SYMLINK+="modem"

        """),

    Rules.new(
        "preserve backslashes, if they are not for a newline",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_links       = ["aaa"],
        ),
        rules = r"""
        KERNEL=="ttyACM0", PROGRAM=="/bin/echo -e \101", RESULT=="A", SYMLINK+="aaa"
        """),

    Rules.new(
        "stupid backslashed multi lines in config file (and don't replace kernel name)",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_links       = ["modem"],
        ),
        rules = r"""

        #
        \

        \

        #\

        KERNEL=="ttyACM0", \
                SYMLINK+="modem"

        """),

    Rules.new(
        "subdirectory handling",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_links       = ["sub/direct/ory/modem"],
        ),
        rules = r"""
        KERNEL=="ttyACM0", SYMLINK+="sub/direct/ory/modem"
        """),

    Rules.new(
        "parent device name match of scsi partition",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
            exp_links       = ["first_disk5"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", KERNELS=="0:0:0:0", SYMLINK+="first_disk%n"
        """),

    Rules.new(
        "test substitution chars",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
            exp_links       = ["Major:8:minor:5:kernelnumber:5:id:0:0:0:0"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", KERNELS=="0:0:0:0", SYMLINK+="Major:%M:minor:%m:kernelnumber:%n:id:%b"
        """),

    Rules.new(
        "import of shell-value returned from program",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["node12345678"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", IMPORT{program}="/bin/echo -e ' TEST_KEY=12345678\n  TEST_key2=98765'", SYMLINK+="node$env{TEST_KEY}"
        KERNEL=="ttyACM0", SYMLINK+="modem"
        """),

    Rules.new(
        "substitution of sysfs value (%s{file})",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["disk-ATA-sda"],
            not_exp_links   = ["modem"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", SYMLINK+="disk-%s{vendor}-%k"
        KERNEL=="ttyACM0", SYMLINK+="modem"
        """),

    Rules.new(
        "program result substitution",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
            exp_links       = ["special-device-5"],
            not_exp_links   = ["not"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", PROGRAM=="/bin/echo -n special-device", RESULT=="-special-*", SYMLINK+="not"
        SUBSYSTEMS=="scsi", PROGRAM=="/bin/echo -n special-device", RESULT=="special-*", SYMLINK+="%c-%n"
        """),

    Rules.new(
        "program result substitution (newline removal)",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
            exp_links       = ["newline_removed"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", PROGRAM=="/bin/echo test", RESULT=="test", SYMLINK+="newline_removed"
        """),

    Rules.new(
        "program result substitution",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
            exp_links       = ["test-0:0:0:0"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", PROGRAM=="/bin/echo -n test-%b", RESULT=="test-0:0*", SYMLINK+="%c"
        """),

    Rules.new(
        "program with lots of arguments",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
            exp_links       = ["foo9"],
            not_exp_links   = ["foo3", "foo4", "foo5", "foo6", "foo7", "foo8"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", PROGRAM=="/bin/echo -n foo3 foo4 foo5 foo6 foo7 foo8 foo9", KERNEL=="sda5", SYMLINK+="%c{7}"
        """),

    Rules.new(
        "program with subshell",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
            exp_links       = ["bar9"],
            not_exp_links   = ["foo3", "foo4", "foo5", "foo6", "foo7", "foo8"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", PROGRAM=="/bin/bash -c 'echo foo3 foo4 foo5 foo6 foo7 foo8 foo9 | sed  s/foo9/bar9/'", KERNEL=="sda5", SYMLINK+="%c{7}"
        """),

    Rules.new(
        "program arguments combined with apostrophes",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
            exp_links       = ["foo7"],
            not_exp_links   = ["foo3", "foo4", "foo5", "foo6", "foo8"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", PROGRAM=="/bin/echo -n 'foo3 foo4'   'foo5   foo6   foo7 foo8'", KERNEL=="sda5", SYMLINK+="%c{5}"
        """),

    Rules.new(
        "program arguments combined with escaped double quotes, part 1",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
            exp_links       = ["foo2"],
            not_exp_links   = ["foo1"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", PROGRAM=="/bin/bash -c 'printf %%s \"foo1 foo2\" | grep \"foo1 foo2\"'", KERNEL=="sda5", SYMLINK+="%c{2}"
        """),

    Rules.new(
        "program arguments combined with escaped double quotes, part 2",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
            exp_links       = ["foo2"],
            not_exp_links   = ["foo1"],
        ),
        rules = r"""
SUBSYSTEMS=="scsi", PROGRAM=="/bin/bash -c \"printf %%s 'foo1 foo2' | grep 'foo1 foo2'\"", KERNEL=="sda5", SYMLINK+="%c{2}"
        """),

    Rules.new(
        "program arguments combined with escaped double quotes, part 3",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
            exp_links       = ["foo2"],
            not_exp_links   = ["foo1", "foo3"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", PROGRAM=="/bin/bash -c 'printf \"%%s %%s\" \"foo1 foo2\" \"foo3\"| grep \"foo1 foo2\"'", KERNEL=="sda5", SYMLINK+="%c{2}"
        """),

    Rules.new(
        "characters before the %c{N} substitution",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
            exp_links       = ["my-foo9"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", PROGRAM=="/bin/echo -n foo3 foo4 foo5 foo6 foo7 foo8 foo9", KERNEL=="sda5", SYMLINK+="my-%c{7}"
        """),

    Rules.new(
        "substitute the second to last argument",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
            exp_links       = ["my-foo8"],
            not_exp_links   = ["my-foo3", "my-foo4", "my-foo5", "my-foo6", "my-foo7", "my-foo9"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", PROGRAM=="/bin/echo -n foo3 foo4 foo5 foo6 foo7 foo8 foo9", KERNEL=="sda5", SYMLINK+="my-%c{6}"
        """),

    Rules.new(
        "test substitution by variable name",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
            exp_links       = ["Major:8-minor:5-kernelnumber:5-id:0:0:0:0"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", KERNELS=="0:0:0:0", SYMLINK+="Major:$major-minor:$minor-kernelnumber:$number-id:$id"
        """),

    Rules.new(
        "test substitution by variable name 2",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
            exp_links       = ["Major:8-minor:5-kernelnumber:5-id:0:0:0:0"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", KERNELS=="0:0:0:0", DEVPATH=="*/sda/*", SYMLINK+="Major:$major-minor:%m-kernelnumber:$number-id:$id"
        """),

    Rules.new(
        "test substitution by variable name 3",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
            exp_links       = ["850:0:0:05"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", KERNELS=="0:0:0:0", DEVPATH=="*/sda/*", SYMLINK+="%M%m%b%n"
        """),

    Rules.new(
        "test substitution by variable name 4",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
            exp_links       = ["855"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", KERNELS=="0:0:0:0", DEVPATH=="*/sda/*", SYMLINK+="$major$minor$number"
        """),

    Rules.new(
        "test substitution by variable name 5",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
            exp_links       = ["8550:0:0:0"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", KERNELS=="0:0:0:0", DEVPATH=="*/sda/*", SYMLINK+="$major%m%n$id"
        """),

    Rules.new(
        "non matching SUBSYSTEMS for device with no parent",
        Device(
            "/devices/virtual/tty/console",
            exp_links       = ["TTY"],
            not_exp_links   = ["foo"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", PROGRAM=="/bin/echo -n foo", RESULT=="foo", SYMLINK+="foo"
        KERNEL=="console", SYMLINK+="TTY"
        """),

    Rules.new(
        "non matching SUBSYSTEMS",
        Device(
            "/devices/virtual/tty/console",
            exp_links       = ["TTY"],
            not_exp_links   = ["foo"],
        ),
        rules = r"""
        SUBSYSTEMS=="foo", ATTRS{dev}=="5:1", SYMLINK+="foo"
        KERNEL=="console", SYMLINK+="TTY"
        """),

    Rules.new(
        "ATTRS match",
        Device(
            "/devices/virtual/tty/console",
            exp_links       = ["foo", "TTY"],
        ),
        rules = r"""
        KERNEL=="console", SYMLINK+="TTY"
        ATTRS{dev}=="5:1", SYMLINK+="foo"
        """),

    Rules.new(
        "ATTR (empty file)",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["empty", "not-something"],
            not_exp_links   = ["something", "not-empty"],
        ),
        rules = r"""
        KERNEL=="sda", ATTR{test_empty_file}=="?*", SYMLINK+="something"
        KERNEL=="sda", ATTR{test_empty_file}!="", SYMLINK+="not-empty"
        KERNEL=="sda", ATTR{test_empty_file}=="", SYMLINK+="empty"
        KERNEL=="sda", ATTR{test_empty_file}!="?*", SYMLINK+="not-something"
        """),

    Rules.new(
        "ATTR (non-existent file)",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["non-existent", "wrong"],
            not_exp_links   = ["something", "empty", "not-empty",
                               "not-something", "something"],
        ),
        rules = r"""
        KERNEL=="sda", ATTR{nofile}=="?*", SYMLINK+="something"
        KERNEL=="sda", ATTR{nofile}!="", SYMLINK+="not-empty"
        KERNEL=="sda", ATTR{nofile}=="", SYMLINK+="empty"
        KERNEL=="sda", ATTR{nofile}!="?*", SYMLINK+="not-something"
        KERNEL=="sda", TEST!="nofile", SYMLINK+="non-existent"
        KERNEL=="sda", SYMLINK+="wrong"
        """),

    Rules.new(
        "program and bus type match",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["scsi-0:0:0:0"],
        ),
        rules = r"""
        SUBSYSTEMS=="usb", PROGRAM=="/bin/echo -n usb-%b", SYMLINK+="%c"
        SUBSYSTEMS=="scsi", PROGRAM=="/bin/echo -n scsi-%b", SYMLINK+="%c"
        SUBSYSTEMS=="foo", PROGRAM=="/bin/echo -n foo-%b", SYMLINK+="%c"
        """),

    Rules.new(
        "sysfs parent hierarchy",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_links       = ["modem"],
        ),
        rules = r"""
        ATTRS{idProduct}=="007b", SYMLINK+="modem"
        """),

    Rules.new(
        "name test with ! in the name",
        Device(
            "/devices/virtual/block/fake!blockdev0",
            devnode         = "fake/blockdev0",
            exp_links       = ["is/a/fake/blockdev0"],
            not_exp_links   = ["is/not/a/fake/blockdev0", "modem"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", SYMLINK+="is/not/a/%k"
        SUBSYSTEM=="block", SYMLINK+="is/a/%k"
        KERNEL=="ttyACM0", SYMLINK+="modem"
        """),

    Rules.new(
        "name test with ! in the name, but no matching rule",
        Device(
            "/devices/virtual/block/fake!blockdev0",
            devnode         = "fake/blockdev0",
            not_exp_links   = ["modem"],
        ),
        rules = r"""
        KERNEL=="ttyACM0", SYMLINK+="modem"
        """),

    Rules.new(
        "KERNELS rule",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["scsi-0:0:0:0"],
            not_exp_links   = ["no-match", "short-id", "not-scsi"],
        ),
        rules = r"""
        SUBSYSTEMS=="usb", KERNELS=="0:0:0:0", SYMLINK+="not-scsi"
        SUBSYSTEMS=="scsi", KERNELS=="0:0:0:1", SYMLINK+="no-match"
        SUBSYSTEMS=="scsi", KERNELS==":0", SYMLINK+="short-id"
        SUBSYSTEMS=="scsi", KERNELS=="/0:0:0:0", SYMLINK+="no-match"
        SUBSYSTEMS=="scsi", KERNELS=="0:0:0:0", SYMLINK+="scsi-0:0:0:0"
        """),

    Rules.new(
        "KERNELS wildcard all",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["scsi-0:0:0:0"],
            not_exp_links   = ["no-match", "before"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", KERNELS=="*:1", SYMLINK+="no-match"
        SUBSYSTEMS=="scsi", KERNELS=="*:0:1", SYMLINK+="no-match"
        SUBSYSTEMS=="scsi", KERNELS=="*:0:0:1", SYMLINK+="no-match"
        SUBSYSTEMS=="scsi", KERNEL=="0:0:0:0", SYMLINK+="before"
        SUBSYSTEMS=="scsi", KERNELS=="*", SYMLINK+="scsi-0:0:0:0"
        """),

    Rules.new(
        "KERNELS wildcard partial",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["scsi-0:0:0:0", "before"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", KERNELS=="0:0:0:0", SYMLINK+="before"
        SUBSYSTEMS=="scsi", KERNELS=="*:0", SYMLINK+="scsi-0:0:0:0"
        """),

    Rules.new(
        "KERNELS wildcard partial 2",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["scsi-0:0:0:0", "before"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", KERNELS=="0:0:0:0", SYMLINK+="before"
        SUBSYSTEMS=="scsi", KERNELS=="*:0:0:0", SYMLINK+="scsi-0:0:0:0"
        """),

    Rules.new(
        "substitute attr with link target value (first match)",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["driver-is-sd"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", SYMLINK+="driver-is-$attr{driver}"
        """),

    Rules.new(
        "substitute attr with link target value (currently selected device)",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["driver-is-ahci"],
        ),
        rules = r"""
        SUBSYSTEMS=="pci", SYMLINK+="driver-is-$attr{driver}"
        """),

    Rules.new(
        "ignore ATTRS attribute whitespace",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["ignored"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", ATTRS{whitespace_test}=="WHITE  SPACE", SYMLINK+="ignored"
        """),

    Rules.new(
        "do not ignore ATTRS attribute whitespace",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["matched-with-space"],
            not_exp_links   = ["wrong-to-ignore"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", ATTRS{whitespace_test}=="WHITE  SPACE ", SYMLINK+="wrong-to-ignore"
        SUBSYSTEMS=="scsi", ATTRS{whitespace_test}=="WHITE  SPACE   ", SYMLINK+="matched-with-space"
        """),

    Rules.new(
        "permissions USER=bad GROUP=name",
        Device(
            "/devices/virtual/tty/tty33",
            exp_perms       = "0:0:0600",
        ),
        rules = r"""
        KERNEL=="tty33", OWNER="bad", GROUP="name"
        """),

    Rules.new(
        "permissions OWNER=1",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["node"],
            exp_perms       = "1::0600",
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", KERNEL=="sda", SYMLINK+="node", OWNER="1"
        """),

    Rules.new(
        "permissions GROUP=1",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["node"],
            exp_perms       = ":1:0660",
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", KERNEL=="sda", SYMLINK+="node", GROUP="1"
        """),

    Rules.new(
        "textual user id",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["node"],
            exp_perms       = "daemon::0600",
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", KERNEL=="sda", SYMLINK+="node", OWNER="daemon"
        """),

    Rules.new(
        "textual group id",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["node"],
            exp_perms       = ":daemon:0660",
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", KERNEL=="sda", SYMLINK+="node", GROUP="daemon"
        """),

    Rules.new(
        "textual user/group id",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["node"],
            exp_perms       = "root:audio:0660",
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", KERNEL=="sda", SYMLINK+="node", OWNER="root", GROUP="audio"
        """),

    Rules.new(
        "permissions MODE=0777",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["node"],
            exp_perms       = "::0777",
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", KERNEL=="sda", SYMLINK+="node", MODE="0777"
        """),

    Rules.new(
        "permissions OWNER=1 GROUP=1 MODE=0777",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["node"],
            exp_perms       = "1:1:0777",
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", KERNEL=="sda", SYMLINK+="node", OWNER="1", GROUP="1", MODE="0777"
        """),

    Rules.new(
        "permissions OWNER to 1",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_perms       = "1::",
        ),
        rules = r"""
        KERNEL=="ttyACM[0-9]*", SYMLINK+="ttyACM%n", OWNER="1"
        """),

    Rules.new(
        "permissions GROUP to 1",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_perms       = ":1:0660",
        ),
        rules = r"""
        KERNEL=="ttyACM[0-9]*", SYMLINK+="ttyACM%n", GROUP="1"
        """),

    Rules.new(
        "permissions MODE to 0060",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_perms       = "::0060",
        ),
        rules = r"""
        KERNEL=="ttyACM[0-9]*", SYMLINK+="ttyACM%n", MODE="0060"
        """),

    Rules.new(
        "permissions OWNER, GROUP, MODE",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_perms       = "1:1:0777",
        ),
        rules = r"""
        KERNEL=="ttyACM[0-9]*", SYMLINK+="ttyACM%n", OWNER="1", GROUP="1", MODE="0777"
        """),

    Rules.new(
        "permissions only rule",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_perms       = "1:1:0777",
        ),
        rules = r"""
        KERNEL=="ttyACM[0-9]*", OWNER="1", GROUP="1", MODE="0777"
        KERNEL=="ttyUSX[0-9]*", OWNER="2", GROUP="2", MODE="0444"
        KERNEL=="ttyACM[0-9]*", SYMLINK+="ttyACM%n"
        """),

    Rules.new(
        "multiple permissions only rule",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_perms       = "1:1:0777",
        ),
        rules = r"""
        SUBSYSTEM=="tty", OWNER="1"
        SUBSYSTEM=="tty", GROUP="1"
        SUBSYSTEM=="tty", MODE="0777"
        KERNEL=="ttyUSX[0-9]*", OWNER="2", GROUP="2", MODE="0444"
        KERNEL=="ttyACM[0-9]*", SYMLINK+="ttyACM%n"
        """),

    Rules.new(
        "permissions only rule with override at SYMLINK+ rule",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_perms       = "1:2:0777",
        ),
        rules = r"""
        SUBSYSTEM=="tty", OWNER="1"
        SUBSYSTEM=="tty", GROUP="1"
        SUBSYSTEM=="tty", MODE="0777"
        KERNEL=="ttyUSX[0-9]*", OWNER="2", GROUP="2", MODE="0444"
        KERNEL=="ttyACM[0-9]*", SYMLINK+="ttyACM%n", GROUP="2"
        """),

    Rules.new(
        "major/minor number test",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["node"],
            exp_major_minor = "8:0",
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", KERNEL=="sda", SYMLINK+="node"
        """),

    Rules.new(
        "big major number test",
        Device(
            "/devices/virtual/misc/misc-fake1",
            exp_links       = ["node"],
            exp_major_minor = "4095:1",
        ),
        rules = r"""
        KERNEL=="misc-fake1", SYMLINK+="node"
        """),

    Rules.new(
        "big major and big minor number test",
        Device(
            "/devices/virtual/misc/misc-fake89999",
            exp_links       = ["node"],
            exp_major_minor = "4095:89999",
        ),
        rules = r"""
        KERNEL=="misc-fake89999", SYMLINK+="node"
        """),

    Rules.new(
        "multiple symlinks with format char",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_links       = ["symlink1-0", "symlink2-ttyACM0", "symlink3-"],
        ),
        rules = r"""
        KERNEL=="ttyACM[0-9]*", SYMLINK="symlink1-%n symlink2-%k symlink3-%b"
        """),

    Rules.new(
        "multiple symlinks with a lot of s p a c e s",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_links       = ["one", "two"],
            not_exp_links       = [" "],
        ),
        rules = r"""
        KERNEL=="ttyACM[0-9]*", SYMLINK="  one     two        "
        """),

    Rules.new(
        "symlink with spaces in substituted variable",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_links       = ["name-one_two_three-end"],
            not_exp_links   = [" "],
        ),
        rules = r"""
        ENV{WITH_WS}="one two three"
        SYMLINK="name-$env{WITH_WS}-end"
        """),

    Rules.new(
        "symlink with leading space in substituted variable",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_links       = ["name-one_two_three-end"],
            not_exp_links   = [" "],
        ),
        rules = r"""
        ENV{WITH_WS}="   one two three"
        SYMLINK="name-$env{WITH_WS}-end"
        """),

    Rules.new(
        "symlink with trailing space in substituted variable",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_links       = ["name-one_two_three-end"],
            not_exp_links   = [" "],
        ),
        rules = r"""
        ENV{WITH_WS}="one two three   "
        SYMLINK="name-$env{WITH_WS}-end"
        """),

    Rules.new(
        "symlink with lots of space in substituted variable",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_links       = ["name-one_two_three-end"],
            not_exp_links   = [" "],
        ),
        rules = r"""
        ENV{WITH_WS}="   one two three   "
        SYMLINK="name-$env{WITH_WS}-end"
        """),

    Rules.new(
        "symlink with multiple spaces in substituted variable",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_links       = ["name-one_two_three-end"],
            not_exp_links   = [" "],
        ),
        rules = r"""
        ENV{WITH_WS}="   one  two  three   "
        SYMLINK="name-$env{WITH_WS}-end"
        """),

    Rules.new(
        "symlink with space and var with space",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_links       = ["first", "name-one_two_three-end",
                               "another_symlink", "a", "b", "c"],
            not_exp_links   = [" "],
        ),
        rules = r"""
        ENV{WITH_WS}="   one  two  three   "
        SYMLINK="  first  name-$env{WITH_WS}-end another_symlink a b c "
        """),

    Rules.new(
        "symlink with env which contain slash (see #19309)",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_links       = ["first", "name-aaa_bbb_ccc-end",
                               "another_symlink", "a", "b", "c"],
            not_exp_links   = ["ame-aaa/bbb/ccc-end"],
        ),
        rules = r"""
        ENV{WITH_SLASH}="aaa/bbb/ccc"
        OPTIONS="string_escape=replace", ENV{REPLACED}="$env{WITH_SLASH}"
        SYMLINK="  first  name-$env{REPLACED}-end another_symlink a b c "
        """),

    Rules.new(
        "symlink creation (same directory)",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_links       = ["modem0"],
        ),
        rules = r"""
        KERNEL=="ttyACM[0-9]*", SYMLINK+="ttyACM%n", SYMLINK="modem%n"
        """),

    Rules.new(
        "multiple symlinks",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_links       = ["first-0", "second-0", "third-0"],
        ),
        rules = r"""
        KERNEL=="ttyACM0", SYMLINK="first-%n second-%n third-%n"
        """),

    Rules.new(
        "symlink name '.'",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
        ),
        # we get a warning, but the process does not fail
        rules = r"""
        SUBSYSTEMS=="scsi", KERNEL=="sda", SYMLINK+="."
        """),

    Rules.new(
        "symlink node to itself",
        Device(
            "/devices/virtual/tty/tty0",
        ),
        # we get a warning, but the process does not fail
        rules = r"""
        KERNEL=="tty0", SYMLINK+="tty0"
        """),

    Rules.new(
        "symlink %n substitution",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_links       = ["symlink0"],
        ),
        rules = r"""
        KERNEL=="ttyACM[0-9]*", SYMLINK+="ttyACM%n", SYMLINK+="symlink%n"
        """),

    Rules.new(
        "symlink %k substitution",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_links       = ["symlink-ttyACM0"],
        ),
        rules = r"""
        KERNEL=="ttyACM[0-9]*", SYMLINK+="ttyACM%n", SYMLINK+="symlink-%k"
        """),

    Rules.new(
        "symlink %M:%m substitution",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_links       = ["major-166:0"],
        ),
        rules = r"""
        KERNEL=="ttyACM[0-9]*", SYMLINK+="ttyACM%n", SYMLINK+="major-%M:%m"
        """),

    Rules.new(
        "symlink %b substitution",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["symlink-0:0:0:0"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", KERNEL=="sda", SYMLINK+="symlink-%b"
        """),

    Rules.new(
        "symlink %c substitution",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_links       = ["test"],
        ),
        rules = r"""
        KERNEL=="ttyACM[0-9]*", PROGRAM=="/bin/echo test", SYMLINK+="%c"
        """),

    Rules.new(
        "symlink %c{N} substitution",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_links       = ["test"],
            not_exp_links   = ["symlink", "this"],
        ),
        rules = r"""
        KERNEL=="ttyACM[0-9]*", PROGRAM=="/bin/echo symlink test this", SYMLINK+="%c{2}"
        """),

    Rules.new(
        "symlink %c{N+} substitution",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_links       = ["test", "this"],
            not_exp_links   = ["symlink"],
        ),
        rules = r"""
        KERNEL=="ttyACM[0-9]*", PROGRAM=="/bin/echo symlink test this", SYMLINK+="%c{2+}"
        """),

    Rules.new(
        "symlink only rule with %c{N+}",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["test", "this"],
            not_exp_links   = ["symlink"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", KERNEL=="sda", PROGRAM=="/bin/echo link test this" SYMLINK+="%c{2+}"
        """),

    Rules.new(
        "symlink %s{filename} substitution",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_links       = ["166:0"],
        ),
        rules = r"""
        KERNEL=="ttyACM[0-9]*", SYMLINK+="%s{dev}"
        """),

    Rules.new(
        "program result substitution (numbered part of)",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
            exp_links       = ["link1", "link2"],
            not_exp_links   = ["node"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", PROGRAM=="/bin/echo -n node link1 link2", RESULT=="node *", SYMLINK+="%c{2} %c{3}"
        """),

    Rules.new(
        "program result substitution (numbered part of+)",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
            exp_links       = ["link1", "link2", "link3", "link4"],
            not_exp_links   = ["node"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", PROGRAM=="/bin/echo -n node link1 link2 link3 link4", RESULT=="node *", SYMLINK+="%c{2+}"
        """),

    Rules.new(
        "SUBSYSTEM match test",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["node"],
            not_exp_links   = ["should_not_match", "should_not_match2"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", KERNEL=="sda", SYMLINK+="should_not_match", SUBSYSTEM=="vc"
        SUBSYSTEMS=="scsi", KERNEL=="sda", SYMLINK+="node", SUBSYSTEM=="block"
        SUBSYSTEMS=="scsi", KERNEL=="sda", SYMLINK+="should_not_match2", SUBSYSTEM=="vc"
        """),

    Rules.new(
        "DRIVERS match test",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["node"],
            not_exp_links   = ["should_not_match"]
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", KERNEL=="sda", SYMLINK+="should_not_match", DRIVERS=="sd-wrong"
        SUBSYSTEMS=="scsi", KERNEL=="sda", SYMLINK+="node", DRIVERS=="sd"
        """),

    Rules.new(
        "devnode substitution test",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["node"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", KERNEL=="sda", PROGRAM=="/usr/bin/test -b %N" SYMLINK+="node"
        """),

    Rules.new(
        "parent node name substitution test",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
            exp_links       = ["sda-part-1"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", KERNEL=="sda1", SYMLINK+="%P-part-%n"
        """),

    Rules.new(
        "udev_root substitution",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
            exp_links       = ["start-/dev-end"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", KERNEL=="sda1", SYMLINK+="start-%r-end"
        """),

    Rules.new(
        # This is not supported any more
        "last_rule option",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
            exp_links       = ["last", "very-last"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", KERNEL=="sda1", SYMLINK+="last", OPTIONS="last_rule"
        SUBSYSTEMS=="scsi", KERNEL=="sda1", SYMLINK+="very-last"
        """),

    Rules.new(
        "negation KERNEL!=",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
            exp_links       = ["match", "before"],
            not_exp_links   = ["matches-but-is-negated"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", KERNEL!="sda1", SYMLINK+="matches-but-is-negated"
        SUBSYSTEMS=="scsi", KERNEL=="sda1", SYMLINK+="before"
        SUBSYSTEMS=="scsi", KERNEL!="xsda1", SYMLINK+="match"
        """),

    Rules.new(
        "negation SUBSYSTEM!=",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
            exp_links       = ["before", "not-anything"],
            not_exp_links   = ["matches-but-is-negated"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", SUBSYSTEM=="block", KERNEL!="sda1", SYMLINK+="matches-but-is-negated"
        SUBSYSTEMS=="scsi", KERNEL=="sda1", SYMLINK+="before"
        SUBSYSTEMS=="scsi", SUBSYSTEM!="anything", SYMLINK+="not-anything"
        """),

    Rules.new(
        "negation PROGRAM!= exit code",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
            exp_links       = ["before", "nonzero-program"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", KERNEL=="sda1", SYMLINK+="before"
        KERNEL=="sda1", PROGRAM!="/bin/false", SYMLINK+="nonzero-program"
        """),

    Rules.new(
        "ENV{} test",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
            exp_links       = ["true"],
            not_exp_links   = ["bad", "wrong"],
        ),
        rules = r"""
        ENV{ENV_KEY_TEST}="test"
        SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ENV_KEY_TEST}=="go", SYMLINK+="wrong"
        SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ENV_KEY_TEST}=="test", SYMLINK+="true"
        SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ENV_KEY_TEST}=="bad", SYMLINK+="bad"
        """),

    Rules.new(
        "ENV{} test",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
            exp_links       = ["true"],
            not_exp_links   = ["bad", "wrong", "no"],
        ),
        rules = r"""
        ENV{ENV_KEY_TEST}="test"
        SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ENV_KEY_TEST}=="go", SYMLINK+="wrong"
        SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ENV_KEY_TEST}=="yes", ENV{ACTION}=="add", ENV{DEVPATH}=="*/block/sda/sdax1", SYMLINK+="no"
        SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ENV_KEY_TEST}=="test", ENV{ACTION}=="add", ENV{DEVPATH}=="*/block/sda/sda1", SYMLINK+="true"
        SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ENV_KEY_TEST}=="bad", SYMLINK+="bad"
        """),

    Rules.new(
        "ENV{} test (assign)",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
            exp_links       = ["true", "before"],
            not_exp_links   = ["no"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ASSIGN}="true"
        SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ASSIGN}=="yes", SYMLINK+="no"
        SUBSYSTEMS=="scsi", KERNEL=="sda1", SYMLINK+="before"
        SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ASSIGN}=="true", SYMLINK+="true"
        """),

    Rules.new(
        "ENV{} test (assign 2 times)",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
            exp_links       = ["true", "before"],
            not_exp_links   = ["no", "bad"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ASSIGN}="true"
        SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ASSIGN}="absolutely-$env{ASSIGN}"
        SUBSYSTEMS=="scsi", KERNEL=="sda1", SYMLINK+="before"
        SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ASSIGN}=="yes", SYMLINK+="no"
        SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ASSIGN}=="true", SYMLINK+="bad"
        SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ASSIGN}=="absolutely-true", SYMLINK+="true"
        """),

    Rules.new(
        "ENV{} test (assign2)",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
            exp_links       = ["part"],
            not_exp_links   = ["disk"],
        ),
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["disk"],
            not_exp_links   = ["part"],
        ),
        rules = r"""
        SUBSYSTEM=="block", KERNEL=="*[0-9]", ENV{PARTITION}="true", ENV{MAINDEVICE}="false"
        SUBSYSTEM=="block", KERNEL=="*[!0-9]", ENV{PARTITION}="false", ENV{MAINDEVICE}="true"
        ENV{MAINDEVICE}=="true", SYMLINK+="disk"
        SUBSYSTEM=="block", SYMLINK+="before"
        ENV{PARTITION}=="true", SYMLINK+="part"
        """),

    Rules.new(
        "untrusted string sanitize",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
            exp_links       = ["sane"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", KERNEL=="sda1", PROGRAM=="/bin/echo -e name; (/usr/bin/badprogram)", RESULT=="name_ _/usr/bin/badprogram_", SYMLINK+="sane"
        """),

    Rules.new(
        "untrusted string sanitize (don't replace utf8)",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
            exp_links       = ["uber"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", KERNEL=="sda1", PROGRAM=="/bin/echo -e \xc3\xbcber" RESULT=="über", SYMLINK+="uber"
        """),

    Rules.new(
        "untrusted string sanitize (replace invalid utf8)",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
            exp_links       = ["replaced"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", KERNEL=="sda1", PROGRAM=="/bin/echo -e \xef\xe8garbage", RESULT=="__garbage", SYMLINK+="replaced"
        """),

    Rules.new(
        "read sysfs value from parent device",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_links       = ["serial-354172020305000"],
        ),
        rules = r"""
        KERNEL=="ttyACM*", ATTRS{serial}=="?*", SYMLINK+="serial-%s{serial}"
        """),

    Rules.new(
        "match against empty key string",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["ok"],
            not_exp_links   = ["not-1-ok", "not-2-ok", "not-3-ok"],
        ),
        rules = r"""
        KERNEL=="sda", ATTRS{nothing}!="", SYMLINK+="not-1-ok"
        KERNEL=="sda", ATTRS{nothing}=="", SYMLINK+="not-2-ok"
        KERNEL=="sda", ATTRS{vendor}!="", SYMLINK+="ok"
        KERNEL=="sda", ATTRS{vendor}=="", SYMLINK+="not-3-ok"
        """),

    Rules.new(
        "check ACTION value",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["ok"],
            not_exp_links   = ["unknown-not-ok"],
        ),
        rules = r"""
        ACTION=="unknown", KERNEL=="sda", SYMLINK+="unknown-not-ok"
        ACTION=="add", KERNEL=="sda", SYMLINK+="ok"
        """),

    Rules.new(
        "final assignment",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["ok"],
            exp_perms       = "root:tty:0640",
        ),
        rules = r"""
        KERNEL=="sda", GROUP:="tty"
        KERNEL=="sda", GROUP="root", MODE="0640", SYMLINK+="ok"
        """),

    Rules.new(
        "final assignment 2",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["ok"],
            exp_perms       = "root:tty:0640",
        ),
        rules = r"""
        KERNEL=="sda", GROUP:="tty"
        SUBSYSTEM=="block", MODE:="640"
        KERNEL=="sda", GROUP="root", MODE="0666", SYMLINK+="ok"
        """),

    Rules.new(
        "env substitution",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["node-add-me"],
        ),
        rules = r"""
        KERNEL=="sda", MODE="0666", SYMLINK+="node-$env{ACTION}-me"
        """),

    Rules.new(
        "reset list to current value",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_links       = ["three"],
            not_exp_links   = ["two", "one"],
        ),
        rules = r"""
        KERNEL=="ttyACM[0-9]*", SYMLINK+="one"
        KERNEL=="ttyACM[0-9]*", SYMLINK+="two"
        KERNEL=="ttyACM[0-9]*", SYMLINK="three"
        """),

    Rules.new(
        "test empty SYMLINK+ (empty override)",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_links       = ["right"],
            not_exp_links   = ["wrong"],
        ),
        rules = r"""
        KERNEL=="ttyACM[0-9]*", SYMLINK+="wrong"
        KERNEL=="ttyACM[0-9]*", SYMLINK=""
        KERNEL=="ttyACM[0-9]*", SYMLINK+="right"
        """),

    Rules.new(
        "test multi matches",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_links       = ["right", "before"],
        ),
        rules = r"""
        KERNEL=="ttyACM*", SYMLINK+="before"
        KERNEL=="ttyACM*|nothing", SYMLINK+="right"
        """),

    Rules.new(
        "test multi matches 2",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_links       = ["right", "before"],
            not_exp_links   = ["nomatch"],
        ),
        rules = r"""
        KERNEL=="dontknow*|*nothing", SYMLINK+="nomatch"
        KERNEL=="ttyACM*", SYMLINK+="before"
        KERNEL=="dontknow*|ttyACM*|nothing*", SYMLINK+="right"
        """),

    Rules.new(
        "test multi matches 3",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_links       = ["right"],
            not_exp_links   = ["nomatch", "wrong1", "wrong2"],
        ),
        rules = r"""
        KERNEL=="dontknow|nothing", SYMLINK+="nomatch"
        KERNEL=="dontknow|ttyACM0a|nothing|attyACM0", SYMLINK+="wrong1"
        KERNEL=="X|attyACM0|dontknow|ttyACM0a|nothing|attyACM0", SYMLINK+="wrong2"
        KERNEL=="dontknow|ttyACM0|nothing", SYMLINK+="right"
        """),

    Rules.new(
        "test multi matches 4",
        Device(
            "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
            exp_links       = ["right"],
            not_exp_links   = ["nomatch", "wrong1", "wrong2", "wrong3"],
        ),
        rules = r"""
        KERNEL=="dontknow|nothing", SYMLINK+="nomatch"
        KERNEL=="dontknow|ttyACM0a|nothing|attyACM0", SYMLINK+="wrong1"
        KERNEL=="X|attyACM0|dontknow|ttyACM0a|nothing|attyACM0", SYMLINK+="wrong2"
        KERNEL=="all|dontknow|ttyACM0", SYMLINK+="right"
        KERNEL=="ttyACM0a|nothing", SYMLINK+="wrong3"
        """),

    Rules.new(
        "test multi matches 5",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["found"],
            not_exp_links   = ["bad"],
        ),
        rules = r"""
        KERNEL=="sda", TAG="foo"
        TAGS=="|foo", SYMLINK+="found"
        TAGS=="|aaa", SYMLINK+="bad"
        """),

    Rules.new(
        "test multi matches 6",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["found"],
            not_exp_links   = ["bad"],
        ),
        rules = r"""
        KERNEL=="sda", ENV{HOGE}=""
        ENV{HOGE}=="|foo", SYMLINK+="found"
        ENV{HOGE}=="aaa|bbb", SYMLINK+="bad"
        """),

    Rules.new(
        "test multi matches 7",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["found"],
            not_exp_links   = ["bad"],
        ),
        rules = r"""
        KERNEL=="sda", TAG="foo"
        TAGS=="foo||bar", SYMLINK+="found"
        TAGS=="aaa||bbb", SYMLINK+="bad"
        """),

    Rules.new(
        "test multi matches 8",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["found"],
            not_exp_links   = ["bad"],
        ),
        rules = r"""
        KERNEL=="sda", ENV{HOGE}=""
        ENV{HOGE}=="foo||bar", SYMLINK+="found"
        ENV{HOGE}=="aaa|bbb", SYMLINK+="bad"
        """),

    Rules.new(
        "test multi matches 9",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["found", "found2"],
            not_exp_links   = ["bad"],
        ),
        rules = r"""
        KERNEL=="sda", TAG="foo"
        TAGS=="foo|", SYMLINK+="found"
        TAGS=="aaa|", SYMLINK+="bad"
        KERNEL=="sda", TAGS!="hoge", SYMLINK+="found2"
        KERNEL=="sda", TAGS!="foo", SYMLINK+="bad2"
        """),

    Rules.new(
        "test multi matches 10",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["found"],
            not_exp_links   = ["bad"],
        ),
        rules = r"""
        KERNEL=="sda", ENV{HOGE}=""
        ENV{HOGE}=="foo|", SYMLINK+="found"
        ENV{HOGE}=="aaa|bbb", SYMLINK+="bad"
        """),

    Rules.new(
        "test multi matches 11",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["found"],
            not_exp_links   = ["bad"],
        ),
        rules = r"""
        KERNEL=="sda", TAG="c"
        TAGS=="foo||bar||c", SYMLINK+="found"
        TAGS=="aaa||bbb||ccc", SYMLINK+="bad"
        """),

    Rules.new(
        "TAG refuses invalid string",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["valid", "found"],
            not_exp_links   = ["empty", "invalid_char", "path", "bad", "bad2"],
        ),
        rules = r"""
       KERNEL=="sda", TAG+="", TAG+="invalid.char", TAG+="path/is/also/invalid", TAG+="valid"
       TAGS=="", SYMLINK+="empty"
       TAGS=="invalid.char", SYMLINK+="invalid_char"
       TAGS=="path/is/also/invalid", SYMLINK+="path"
       TAGS=="valid", SYMLINK+="valid"
       TAGS=="valid|", SYMLINK+="found"
       TAGS=="aaa|", SYMLINK+="bad"
       TAGS=="aaa|bbb", SYMLINK+="bad2"
        """),

    Rules.new(
        "IMPORT parent test",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["parent"],
        ),
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
            exp_links       = ["parentenv-parent_right"],
        ),
        delay = 500000,  # Serialized! We need to sleep here after adding sda
        rules = r"""
        KERNEL=="sda1", IMPORT{parent}="PARENT*", SYMLINK+="parentenv-$env{PARENT_KEY}$env{WRONG_PARENT_KEY}"
        KERNEL=="sda", IMPORT{program}="/bin/echo -e 'PARENT_KEY=parent_right\nWRONG_PARENT_KEY=parent_wrong'"
        KERNEL=="sda", SYMLINK+="parent"
        """),

    Rules.new(
        "GOTO test",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
            exp_links       = ["right"],
            not_exp_links   = ["wrong", "wrong2"],
        ),
        rules = r"""
        KERNEL=="sda1", GOTO="TEST"
        KERNEL=="sda1", SYMLINK+="wrong"
        KERNEL=="sda1", GOTO="BAD"
        KERNEL=="sda1", SYMLINK+="", LABEL="NO"
        KERNEL=="sda1", SYMLINK+="right", LABEL="TEST", GOTO="end"
        KERNEL=="sda1", SYMLINK+="wrong2", LABEL="BAD"
        LABEL="end"
        """),

    Rules.new(
        "GOTO label does not exist",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
            exp_links       = ["right"],
        ),
        rules = r"""
        KERNEL=="sda1", GOTO="does-not-exist"
        KERNEL=="sda1", SYMLINK+="right",
        LABEL="exists"
        """),

    Rules.new(
        "SYMLINK+ compare test",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
            exp_links       = ["right", "link"],
            not_exp_links   = ["wrong"],
        ),
        rules = r"""
        KERNEL=="sda1", SYMLINK+="link"
        KERNEL=="sda1", SYMLINK=="link*", SYMLINK+="right"
        KERNEL=="sda1", SYMLINK=="nolink*", SYMLINK+="wrong"
        """),

    Rules.new(
        "invalid key operation",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
            exp_links       = ["yes"],
            not_exp_links   = ["no"],
        ),
        rules = r"""
        KERNEL="sda1", SYMLINK+="no"
        KERNEL=="sda1", SYMLINK+="yes"
        """),

    Rules.new(
        "operator chars in attribute",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["yes"],
        ),
        rules = r"""
        KERNEL=="sda", ATTR{test:colon+plus}=="?*", SYMLINK+="yes"
        """),

    Rules.new(
        "overlong comment line",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
            exp_links       = ["yes"],
            not_exp_links   = ["no"],
        ),
        rules = r"""
        # 012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789
           # 012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789
        KERNEL=="sda1", SYMLINK+=="no"
        KERNEL=="sda1", SYMLINK+="yes"
        """),

    Rules.new(
        "magic subsys/kernel lookup",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["00:16:41:e2:8d:ff"],
        ),
        rules = r"""
        KERNEL=="sda", SYMLINK+="$attr{[net/eth0]address}"
        """),

    Rules.new(
        "TEST absolute path",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["there"],
            not_exp_links   = ["notthere"],
        ),
        rules = r"""
        TEST=="/etc/passwd", SYMLINK+="there"
        TEST!="/etc/passwd", SYMLINK+="notthere"
        """),

    Rules.new(
        "TEST subsys/kernel lookup",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["yes"],
        ),
        rules = r"""
        KERNEL=="sda", TEST=="[net/eth0]", SYMLINK+="yes"
        """),

    Rules.new(
        "TEST relative path",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["relative"],
        ),
        rules = r"""
        KERNEL=="sda", TEST=="size", SYMLINK+="relative"
        """),

    Rules.new(
        "TEST wildcard substitution (find queue/nr_requests)",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["found-subdir"],
        ),
        rules = r"""
        KERNEL=="sda", TEST=="*/nr_requests", SYMLINK+="found-subdir"
        """),

    Rules.new(
        "TEST MODE=0000",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_perms        = "0:0:0000",
        ),
        rules = r"""
        KERNEL=="sda", MODE="0000"
        """),

    Rules.new(
        "TEST PROGRAM feeds OWNER, GROUP, MODE",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_perms       = "1:1:0400",
        ),
        rules = r"""
        KERNEL=="sda", MODE="666"
        KERNEL=="sda", PROGRAM=="/bin/echo 1 1 0400", OWNER="%c{1}", GROUP="%c{2}", MODE="%c{3}"
        """),

    Rules.new(
        "TEST PROGRAM feeds MODE with overflow",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_perms        = "0:0:0440",
        ),
        rules = r"""
        KERNEL=="sda", MODE="440"
        KERNEL=="sda", PROGRAM=="/bin/echo 0 0 0400letsdoabuffferoverflow0123456789012345789012345678901234567890", OWNER="%c{1}", GROUP="%c{2}", MODE="%c{3}"
        """),

    Rules.new(
        "magic [subsys/sysname] attribute substitution",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["sda-8741C4G-end"],
            exp_perms       = "0:0:0600",
        ),
        rules = r"""
        KERNEL=="sda", SYMLINK+="%k-%s{[dmi/id]product_name}-end"
        """),

    Rules.new(
        "builtin path_id",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["disk/by-path/pci-0000:00:1f.2-scsi-0:0:0:0"],
        ),
        rules = r"""
        KERNEL=="sda", IMPORT{builtin}="path_id"
        KERNEL=="sda", ENV{ID_PATH}=="?*", SYMLINK+="disk/by-path/$env{ID_PATH}"
        """),

    Rules.new(
        "add and match tag",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["found"],
            not_exp_links   = ["bad"],
        ),
        rules = r"""
        SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", TAG+="green"
        TAGS=="green", SYMLINK+="found"
        TAGS=="blue", SYMLINK+="bad"
        """),

    Rules.new(
        "don't crash with lots of tags",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["found"],
        ),
        rules = f"""
        {rules_10k_tags}
        TAGS=="test1", TAGS=="test500", TAGS=="test1234", TAGS=="test9999", TAGS=="test10000", SYMLINK+="found"
        """),

    Rules.new(
        "continuations",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["found"],
            not_exp_links   = ["bad"],
        ),
        rules = f"""
        {rules_10k_tags_continuation}
        TAGS=="test1", TAGS=="test500", TAGS=="test1234", TAGS=="test9999", TAGS=="test10000", SYMLINK+="bad"
        KERNEL=="sda",\\
        # comment in continuation
        TAG+="hoge1",\\
          # space before comment
        TAG+="hoge2",\\
        # spaces before and after token are dropped
          TAG+="hoge3",   \\
        \\
         \\
        TAG+="hoge4"
        TAGS=="hoge1", TAGS=="hoge2", TAGS=="hoge3", TAGS=="hoge4", SYMLINK+="found"
        """),

    Rules.new(
        "continuations with empty line",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["found"],
            not_exp_links   = ["bad"],
        ),
        rules = r"""
        # empty line finishes continuation
        KERNEL=="sda", TAG+="foo" \

        KERNEL=="sdb", TAG+="hoge"
        KERNEL=="sda", TAG+="aaa" \
        KERNEL=="sdb", TAG+="bbb"
        TAGS=="foo", SYMLINK+="found"
        TAGS=="aaa", SYMLINK+="bad"
        """),

    Rules.new(
        "continuations with space only line",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            exp_links       = ["found"],
            not_exp_links   = ["bad"],
        ),
        rules = """
        # space only line finishes continuation
        KERNEL=="sda", TAG+="foo" \\
           \t
        KERNEL=="sdb", TAG+="hoge"
        KERNEL=="sda", TAG+="aaa" \\
        KERNEL=="sdb", TAG+="bbb"
        TAGS=="foo", SYMLINK+="found"
        TAGS=="aaa", SYMLINK+="bad"
        """),

    Rules.new(
        "multiple devices",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
            exp_links       = ["part-1"],
        ),
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
            exp_links       = ["part-5"],
        ),
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda6",
            exp_links       = ["part-6"],
        ),
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda7",
            exp_links       = ["part-7"],
        ),
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda8",
            exp_links       = ["part-8"],
        ),
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda9",
            exp_links       = ["part-9"],
        ),
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda10",
            exp_links       = ["part-10"],
        ),
        rules = r"""
        SUBSYSTEM=="block", SUBSYSTEMS=="scsi", KERNEL=="sda?*", ENV{DEVTYPE}=="partition", SYMLINK+="part-%n"
        """),

    Rules.new(
        "multiple devices, same link name, positive prio",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
            exp_links       = ["part-1"],
            not_exp_links   = ["partition"],
        ),
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
            exp_links       = ["part-5"],
            not_exp_links   = ["partition"],
        ),
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda6",
            not_exp_links   = ["partition"],
            exp_links       = ["part-6"],
        ),
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda7",
            exp_links       = ["part-7", "partition"],
        ),
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda8",
            not_exp_links   = ["partition"],
            exp_links       = ["part-8"],
        ),
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda9",
            not_exp_links   = ["partition"],
            exp_links       = ["part-9"],
        ),
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda10",
            not_exp_links   = ["partition"],
            exp_links       = ["part-10"],
        ),
        repeat          = 100,
        rules = r"""
        SUBSYSTEM=="block", SUBSYSTEMS=="scsi", KERNEL=="sda?*", ENV{DEVTYPE}=="partition", SYMLINK+="part-%n"
        SUBSYSTEM=="block", SUBSYSTEMS=="scsi", KERNEL=="sda?*", ENV{DEVTYPE}=="partition", SYMLINK+="partition"
        KERNEL=="*7", OPTIONS+="link_priority=10"
        """),

    Rules.new(
        "multiple devices, same link name, negative prio",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
            exp_links       = ["part-1"],
            not_exp_links   = ["partition"],
        ),
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
            exp_links       = ["part-5"],
            not_exp_links   = ["partition"],
        ),
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda6",
            not_exp_links   = ["partition"],
            exp_links       = ["part-6"],
        ),
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda7",
            exp_links       = ["part-7", "partition"],
        ),
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda8",
            not_exp_links   = ["partition"],
            exp_links       = ["part-8"],
        ),
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda9",
            not_exp_links   = ["partition"],
            exp_links       = ["part-9"],
        ),
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda10",
            not_exp_links   = ["partition"],
            exp_links       = ["part-10"],
        ),
        rules = r"""
        SUBSYSTEM=="block", SUBSYSTEMS=="scsi", KERNEL=="sda?*", ENV{DEVTYPE}=="partition", SYMLINK+="part-%n"
        SUBSYSTEM=="block", SUBSYSTEMS=="scsi", KERNEL=="sda?*", ENV{DEVTYPE}=="partition", SYMLINK+="partition"
        KERNEL!="*7", OPTIONS+="link_priority=-10"
        """),

    Rules.new(
        "multiple devices, same link name, positive prio, sleep",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
            exp_links       = ["part-1"],
            not_exp_links   = ["partition"],
        ),
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
            exp_links       = ["part-5"],
            not_exp_links   = ["partition"],
        ),
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda6",
            not_exp_links   = ["partition"],
            exp_links       = ["part-6"],
        ),
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda7",
            exp_links       = ["part-7", "partition"],
        ),
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda8",
            not_exp_links   = ["partition"],
            exp_links       = ["part-8"],
        ),
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda9",
            not_exp_links   = ["partition"],
            exp_links       = ["part-9"],
        ),
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda10",
            not_exp_links   = ["partition"],
            exp_links       = ["part-10"],
        ),
        delay = 10000,
        rules = r"""
        SUBSYSTEM=="block", SUBSYSTEMS=="scsi", KERNEL=="sda?*", ENV{DEVTYPE}=="partition", SYMLINK+="part-%n"
        SUBSYSTEM=="block", SUBSYSTEMS=="scsi", KERNEL=="sda?*", ENV{DEVTYPE}=="partition", SYMLINK+="partition"
        KERNEL=="*7", OPTIONS+="link_priority=10"
        """),

    Rules.new(
        'all_block_devs',
        device_generator = lambda: \
            all_block_devs(lambda name: (["blockdev"], None) if name.endswith('/sda6') else (None, None)),
        repeat = 10,
        rules  = r"""
        SUBSYSTEM=="block", SUBSYSTEMS=="scsi", KERNEL=="sd*", SYMLINK+="blockdev"
        KERNEL=="sda6", OPTIONS+="link_priority=10"
        """),

    Rules.new(
        "case insensitive match",
        Device(
            "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
            exp_links     = ["ok"],
        ),

        rules = r"""
        KERNEL==i"SDA1", SUBSYSTEMS==i"SCSI", ATTRS{vendor}==i"a?a", SYMLINK+="ok"
        """),
]

def fork_and_run_udev(action: str, rules: Rules) -> None:
    kinder = []
    for k, device in enumerate(rules.devices):
        # TODO: valgrind/gdb/strace
        cmd = [UDEV_BIN, action, device.devpath]
        if rules.delay:
            cmd += [f'{k * rules.delay}']

        kinder += [subprocess.Popen(cmd)]

    good = True
    for c in kinder:
        if not good:
            # once something fails, terminate all workers
            c.terminate()
        elif c.wait() != 0:
            good = False

    assert good


def environment_issue():
    if os.getuid() != 0:
        return 'Must be root to run properly'

    c = subprocess.run(['systemd-detect-virt', '-r', '-q'],
                       check=False)
    if c.returncode == 0:
        return 'Running in a chroot, skipping the test'

    c = subprocess.run(['systemd-detect-virt', '-c', '-q'],
                       check=False)
    if c.returncode == 0:
        return 'Running in a container, skipping the test'

    return None


@pytest.fixture(scope='module')
def udev_setup():
    issue = environment_issue()
    if issue:
        pytest.skip(issue)

    global UDEV_RUN, UDEV_RULES, UDEV_DEV, UDEV_SYS

    _tmpdir = tempfile.TemporaryDirectory()
    tmpdir = Path(_tmpdir.name)

    UDEV_RUN   = tmpdir / 'run'
    UDEV_RULES = UDEV_RUN / 'udev-test.rules'

    udev_tmpfs = tmpdir / 'tmpfs'
    UDEV_DEV   = udev_tmpfs / 'dev'
    UDEV_SYS   = udev_tmpfs / 'sys'

    subprocess.run(['umount', udev_tmpfs],
                   stderr=subprocess.DEVNULL,
                   check=False)
    udev_tmpfs.mkdir(exist_ok=True, parents=True)

    subprocess.check_call(['mount', '-v',
                                    '-t', 'tmpfs',
                                    '-o', 'rw,mode=0755,nosuid,noexec',
                                    'tmpfs', udev_tmpfs])

    UDEV_DEV.mkdir(exist_ok=True)
    # setting group and mode of udev_dev ensures the tests work
    # even if the parent directory has setgid bit enabled.
    os.chmod(UDEV_DEV,0o755)
    os.chown(UDEV_DEV, 0, 0)

    os.mknod(UDEV_DEV / 'null', 0o600 | stat.S_IFCHR, os.makedev(1, 3))

    # check if we are permitted to create block device nodes
    sda = UDEV_DEV / 'sda'
    os.mknod(sda, 0o600 | stat.S_IFBLK, os.makedev(8, 0))
    sda.unlink()

    subprocess.check_call([SYS_SCRIPT, UDEV_SYS.parent])
    subprocess.check_call(['rm', '-rf', UDEV_RUN])
    UDEV_RUN.mkdir(parents=True)

    os.chdir(tmpdir)

    if subprocess.run([UDEV_BIN, 'check'],
                      check=False).returncode != 0:
        pytest.skip(f'{UDEV_BIN} failed to set up the environment, skipping the test',
                    allow_module_level=True)

    yield

    subprocess.check_call(['rm', '-rf', UDEV_RUN])
    subprocess.check_call(['umount', '-v', udev_tmpfs])
    udev_tmpfs.rmdir()


@pytest.mark.parametrize("rules", RULES, ids=(rule.desc for rule in RULES))
def test_udev(rules: Rules, udev_setup):
    assert udev_setup is None

    rules.create_rules_file()
    rules.generate_devices()

    for _ in range(rules.repeat):
        fork_and_run_udev('add', rules)

        for device in rules.devices:
            device.check_add()

        fork_and_run_udev('remove', rules)

        for device in rules.devices:
            device.check_remove()

if __name__ == '__main__':
    issue = environment_issue()
    if issue:
        print(issue, file=sys.stderr)
        sys.exit(77)
    sys.exit(pytest.main(sys.argv))
