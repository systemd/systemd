#!/usr/bin/perl

# udev test
#
# Provides automated testing of the udev binary.
# The whole test is self contained in this file, except the matching sysfs tree.
# Simply extend the @tests array, to add a new test variant.
#
# Every test is driven by its own temporary config file.
# This program prepares the environment, creates the config and calls udev.
#
# udev parses the rules, looks at the provided sysfs and
# first creates and then removes the device node.
# After creation and removal the result is checked against the
# expected value and the result is printed.
#
# Copyright (C) 2004-2012 Kay Sievers <kay@vrfy.org>
# Copyright (C) 2004 Leann Ogasawara <ogasawara@osdl.org>

use warnings;
use strict;

my $udev_bin            = "./test-udev";
my $valgrind            = 0;
my $gdb                 = 0;
my $udev_bin_valgrind   = "valgrind --tool=memcheck --leak-check=yes --track-origins=yes --quiet $udev_bin";
my $udev_bin_gdb        = "gdb --args $udev_bin";
my $udev_dev            = "test/dev";
my $udev_run            = "test/run";
my $udev_rules_dir      = "$udev_run/udev/rules.d";
my $udev_rules          = "$udev_rules_dir/udev-test.rules";
my $EXIT_TEST_SKIP      = 77;

my @tests = (
        {
                desc            => "no rules",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "sda" ,
                exp_rem_error   => "yes",
                rules           => <<EOF
#
EOF
        },
        {
                desc            => "label test of scsi disc",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "boot_disk" ,
                rules           => <<EOF
SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", SYMLINK+="boot_disk%n"
KERNEL=="ttyACM0", SYMLINK+="modem"
EOF
        },
        {
                desc            => "label test of scsi disc",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "boot_disk" ,
                rules           => <<EOF
SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", SYMLINK+="boot_disk%n"
KERNEL=="ttyACM0", SYMLINK+="modem"
EOF
        },
        {
                desc            => "label test of scsi disc",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "boot_disk" ,
                rules           => <<EOF
SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", SYMLINK+="boot_disk%n"
KERNEL=="ttyACM0", SYMLINK+="modem"
EOF
        },
        {
                desc            => "label test of scsi partition",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
                exp_name        => "boot_disk1" ,
                rules           => <<EOF
SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", SYMLINK+="boot_disk%n"
EOF
        },
        {
                desc            => "label test of pattern match",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
                exp_name        => "boot_disk1" ,
                rules           => <<EOF
SUBSYSTEMS=="scsi", ATTRS{vendor}=="?ATA", SYMLINK+="boot_disk%n-1"
SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA?", SYMLINK+="boot_disk%n-2"
SUBSYSTEMS=="scsi", ATTRS{vendor}=="A??", SYMLINK+="boot_disk%n"
SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATAS", SYMLINK+="boot_disk%n-3"
EOF
        },
        {
                desc            => "label test of multiple sysfs files",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
                exp_name        => "boot_disk1" ,
                rules           => <<EOF
SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", ATTRS{model}=="ST910021AS X ", SYMLINK+="boot_diskX%n"
SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", ATTRS{model}=="ST910021AS", SYMLINK+="boot_disk%n"
EOF
        },
        {
                desc            => "label test of max sysfs files (skip invalid rule)",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
                exp_name        => "boot_disk1" ,
                rules           => <<EOF
SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", ATTRS{model}=="ST910021AS", ATTRS{scsi_level}=="6", ATTRS{rev}=="4.06", ATTRS{type}=="0", ATTRS{queue_depth}=="32", SYMLINK+="boot_diskXX%n"
SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", ATTRS{model}=="ST910021AS", ATTRS{scsi_level}=="6", ATTRS{rev}=="4.06", ATTRS{type}=="0", SYMLINK+="boot_disk%n"
EOF
        },
        {
                desc            => "catch device by *",
                devpath         => "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
                exp_name        => "modem/0" ,
                rules           => <<EOF
KERNEL=="ttyACM*", SYMLINK+="modem/%n"
EOF
        },
        {
                desc            => "catch device by * - take 2",
                devpath         => "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
                exp_name        => "modem/0" ,
                rules           => <<EOF
KERNEL=="*ACM1", SYMLINK+="bad"
KERNEL=="*ACM0", SYMLINK+="modem/%n"
EOF
        },
        {
                desc            => "catch device by ?",
                devpath         => "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
                exp_name        => "modem/0" ,
                rules           => <<EOF
KERNEL=="ttyACM??*", SYMLINK+="modem/%n-1"
KERNEL=="ttyACM??", SYMLINK+="modem/%n-2"
KERNEL=="ttyACM?", SYMLINK+="modem/%n"
EOF
        },
        {
                desc            => "catch device by character class",
                devpath         => "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
                exp_name        => "modem/0" ,
                rules           => <<EOF
KERNEL=="ttyACM[A-Z]*", SYMLINK+="modem/%n-1"
KERNEL=="ttyACM?[0-9]", SYMLINK+="modem/%n-2"
KERNEL=="ttyACM[0-9]*", SYMLINK+="modem/%n"
EOF
        },
        {
                desc            => "replace kernel name",
                devpath         => "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
                exp_name        => "modem" ,
                rules           => <<EOF
KERNEL=="ttyACM0", SYMLINK+="modem"
EOF
        },
        {
                desc            => "Handle comment lines in config file (and replace kernel name)",
                devpath         => "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
                exp_name        => "modem" ,
                rules           => <<EOF
# this is a comment
KERNEL=="ttyACM0", SYMLINK+="modem"

EOF
        },
        {
                desc            => "Handle comment lines in config file with whitespace (and replace kernel name)",
                devpath         => "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
                exp_name        => "modem" ,
                rules           => <<EOF
 # this is a comment with whitespace before the comment
KERNEL=="ttyACM0", SYMLINK+="modem"

EOF
        },
        {
                desc            => "Handle whitespace only lines (and replace kernel name)",
                devpath         => "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
                exp_name        => "whitespace" ,
                rules           => <<EOF



 # this is a comment with whitespace before the comment
KERNEL=="ttyACM0", SYMLINK+="whitespace"



EOF
        },
        {
                desc            => "Handle empty lines in config file (and replace kernel name)",
                devpath         => "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
                exp_name        => "modem" ,
                rules           => <<EOF

KERNEL=="ttyACM0", SYMLINK+="modem"

EOF
        },
        {
                desc            => "Handle backslashed multi lines in config file (and replace kernel name)",
                devpath         => "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
                exp_name        => "modem" ,
                rules           => <<EOF
KERNEL=="ttyACM0", \\
SYMLINK+="modem"

EOF
        },
        {
                desc            => "preserve backslashes, if they are not for a newline",
                devpath         => "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
                exp_name        => "aaa",
                rules           => <<EOF
KERNEL=="ttyACM0", PROGRAM=="/bin/echo -e \\101", RESULT=="A", SYMLINK+="aaa"
EOF
        },
        {
                desc            => "Handle stupid backslashed multi lines in config file (and replace kernel name)",
                devpath         => "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
                exp_name        => "modem" ,
                rules           => <<EOF

#
\\

\\

#\\

KERNEL=="ttyACM0", \\
        SYMLINK+="modem"

EOF
        },
        {
                desc            => "subdirectory handling",
                devpath         => "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
                exp_name        => "sub/direct/ory/modem" ,
                rules           => <<EOF
KERNEL=="ttyACM0", SYMLINK+="sub/direct/ory/modem"
EOF
        },
        {
                desc            => "parent device name match of scsi partition",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
                exp_name        => "first_disk5" ,
                rules           => <<EOF
SUBSYSTEMS=="scsi", KERNELS=="0:0:0:0", SYMLINK+="first_disk%n"
EOF
        },
        {
                desc            => "test substitution chars",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
                exp_name        => "Major:8:minor:5:kernelnumber:5:id:0:0:0:0" ,
                rules           => <<EOF
SUBSYSTEMS=="scsi", KERNELS=="0:0:0:0", SYMLINK+="Major:%M:minor:%m:kernelnumber:%n:id:%b"
EOF
        },
        {
                desc            => "import of shell-value returned from program",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "node12345678",
                rules           => <<EOF
SUBSYSTEMS=="scsi", IMPORT{program}="/bin/echo -e \' TEST_KEY=12345678\\n  TEST_key2=98765\'", SYMLINK+="node\$env{TEST_KEY}"
KERNEL=="ttyACM0", SYMLINK+="modem"
EOF
        },
        {
                desc            => "sustitution of sysfs value (%s{file})",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "disk-ATA-sda" ,
                rules           => <<EOF
SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", SYMLINK+="disk-%s{vendor}-%k"
KERNEL=="ttyACM0", SYMLINK+="modem"
EOF
        },
        {
                desc            => "program result substitution",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
                exp_name        => "special-device-5" ,
                not_exp_name    => "not" ,
                rules           => <<EOF
SUBSYSTEMS=="scsi", PROGRAM=="/bin/echo -n special-device", RESULT=="-special-*", SYMLINK+="not"
SUBSYSTEMS=="scsi", PROGRAM=="/bin/echo -n special-device", RESULT=="special-*", SYMLINK+="%c-%n"
EOF
        },
        {
                desc            => "program result substitution (newline removal)",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
                exp_name        => "newline_removed" ,
                rules           => <<EOF
SUBSYSTEMS=="scsi", PROGRAM=="/bin/echo test", RESULT=="test", SYMLINK+="newline_removed"
EOF
        },
        {
                desc            => "program result substitution",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
                exp_name        => "test-0:0:0:0" ,
                rules           => <<EOF
SUBSYSTEMS=="scsi", PROGRAM=="/bin/echo -n test-%b", RESULT=="test-0:0*", SYMLINK+="%c"
EOF
        },
        {
                desc            => "program with lots of arguments",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
                exp_name        => "foo9" ,
                rules           => <<EOF
SUBSYSTEMS=="scsi", PROGRAM=="/bin/echo -n foo3 foo4 foo5 foo6 foo7 foo8 foo9", KERNEL=="sda5", SYMLINK+="%c{7}"
EOF
        },
        {
                desc            => "program with subshell",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
                exp_name        => "bar9" ,
                rules           => <<EOF
SUBSYSTEMS=="scsi", PROGRAM=="/bin/sh -c 'echo foo3 foo4 foo5 foo6 foo7 foo8 foo9 | sed  s/foo9/bar9/'", KERNEL=="sda5", SYMLINK+="%c{7}"
EOF
        },
        {
                desc            => "program arguments combined with apostrophes",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
                exp_name        => "foo7" ,
                rules           => <<EOF
SUBSYSTEMS=="scsi", PROGRAM=="/bin/echo -n 'foo3 foo4'   'foo5   foo6   foo7 foo8'", KERNEL=="sda5", SYMLINK+="%c{5}"
EOF
        },
        {
                desc            => "characters before the %c{N} substitution",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
                exp_name        => "my-foo9" ,
                rules           => <<EOF
SUBSYSTEMS=="scsi", PROGRAM=="/bin/echo -n foo3 foo4 foo5 foo6 foo7 foo8 foo9", KERNEL=="sda5", SYMLINK+="my-%c{7}"
EOF
        },
        {
                desc            => "substitute the second to last argument",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
                exp_name        => "my-foo8" ,
                rules           => <<EOF
SUBSYSTEMS=="scsi", PROGRAM=="/bin/echo -n foo3 foo4 foo5 foo6 foo7 foo8 foo9", KERNEL=="sda5", SYMLINK+="my-%c{6}"
EOF
        },
        {
                desc            => "test substitution by variable name",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
                exp_name        => "Major:8-minor:5-kernelnumber:5-id:0:0:0:0",
                rules           => <<EOF
SUBSYSTEMS=="scsi", KERNELS=="0:0:0:0", SYMLINK+="Major:\$major-minor:\$minor-kernelnumber:\$number-id:\$id"
EOF
        },
        {
                desc            => "test substitution by variable name 2",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
                exp_name        => "Major:8-minor:5-kernelnumber:5-id:0:0:0:0",
                rules           => <<EOF
SUBSYSTEMS=="scsi", KERNELS=="0:0:0:0", DEVPATH=="*/sda/*", SYMLINK+="Major:\$major-minor:%m-kernelnumber:\$number-id:\$id"
EOF
        },
        {
                desc            => "test substitution by variable name 3",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
                exp_name        => "850:0:0:05" ,
                rules           => <<EOF
SUBSYSTEMS=="scsi", KERNELS=="0:0:0:0", DEVPATH=="*/sda/*", SYMLINK+="%M%m%b%n"
EOF
        },
        {
                desc            => "test substitution by variable name 4",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
                exp_name        => "855" ,
                rules           => <<EOF
SUBSYSTEMS=="scsi", KERNELS=="0:0:0:0", DEVPATH=="*/sda/*", SYMLINK+="\$major\$minor\$number"
EOF
        },
        {
                desc            => "test substitution by variable name 5",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
                exp_name        => "8550:0:0:0" ,
                rules           => <<EOF
SUBSYSTEMS=="scsi", KERNELS=="0:0:0:0", DEVPATH=="*/sda/*", SYMLINK+="\$major%m%n\$id"
EOF
        },
        {
                desc            => "non matching SUBSYSTEMS for device with no parent",
                devpath         => "/devices/virtual/tty/console",
                exp_name        => "TTY",
                rules           => <<EOF
SUBSYSTEMS=="scsi", PROGRAM=="/bin/echo -n foo", RESULT=="foo", SYMLINK+="foo"
KERNEL=="console", SYMLINK+="TTY"
EOF
        },
        {
                desc            => "non matching SUBSYSTEMS",
                devpath         => "/devices/virtual/tty/console",
                exp_name        => "TTY" ,
                rules                => <<EOF
SUBSYSTEMS=="foo", ATTRS{dev}=="5:1", SYMLINK+="foo"
KERNEL=="console", SYMLINK+="TTY"
EOF
        },
        {
                desc            => "ATTRS match",
                devpath         => "/devices/virtual/tty/console",
                exp_name        => "foo" ,
                rules           => <<EOF
KERNEL=="console", SYMLINK+="TTY"
ATTRS{dev}=="5:1", SYMLINK+="foo"
EOF
        },
        {
                desc            => "ATTR (empty file)",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "empty" ,
                rules           => <<EOF
KERNEL=="sda", ATTR{test_empty_file}=="?*", SYMLINK+="something"
KERNEL=="sda", ATTR{test_empty_file}!="", SYMLINK+="not-empty"
KERNEL=="sda", ATTR{test_empty_file}=="", SYMLINK+="empty"
KERNEL=="sda", ATTR{test_empty_file}!="?*", SYMLINK+="not-something"
EOF
        },
        {
                desc            => "ATTR (non-existent file)",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "non-existent" ,
                rules           => <<EOF
KERNEL=="sda", ATTR{nofile}=="?*", SYMLINK+="something"
KERNEL=="sda", ATTR{nofile}!="", SYMLINK+="not-empty"
KERNEL=="sda", ATTR{nofile}=="", SYMLINK+="empty"
KERNEL=="sda", ATTR{nofile}!="?*", SYMLINK+="not-something"
KERNEL=="sda", TEST!="nofile", SYMLINK+="non-existent"
KERNEL=="sda", SYMLINK+="wrong"
EOF
        },
        {
                desc            => "program and bus type match",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "scsi-0:0:0:0" ,
                rules           => <<EOF
SUBSYSTEMS=="usb", PROGRAM=="/bin/echo -n usb-%b", SYMLINK+="%c"
SUBSYSTEMS=="scsi", PROGRAM=="/bin/echo -n scsi-%b", SYMLINK+="%c"
SUBSYSTEMS=="foo", PROGRAM=="/bin/echo -n foo-%b", SYMLINK+="%c"
EOF
        },
        {
                desc            => "sysfs parent hierarchy",
                devpath         => "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
                exp_name        => "modem" ,
                rules           => <<EOF
ATTRS{idProduct}=="007b", SYMLINK+="modem"
EOF
        },
        {
                desc            => "name test with ! in the name",
                devpath         => "/devices/virtual/block/fake!blockdev0",
                exp_name        => "is/a/fake/blockdev0" ,
                rules           => <<EOF
SUBSYSTEMS=="scsi", SYMLINK+="is/not/a/%k"
SUBSYSTEM=="block", SYMLINK+="is/a/%k"
KERNEL=="ttyACM0", SYMLINK+="modem"
EOF
        },
        {
                desc            => "name test with ! in the name, but no matching rule",
                devpath         => "/devices/virtual/block/fake!blockdev0",
                exp_name        => "fake/blockdev0" ,
                exp_rem_error   => "yes",
                rules           => <<EOF
KERNEL=="ttyACM0", SYMLINK+="modem"
EOF
        },
        {
                desc            => "KERNELS rule",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "scsi-0:0:0:0",
                rules           => <<EOF
SUBSYSTEMS=="usb", KERNELS=="0:0:0:0", SYMLINK+="not-scsi"
SUBSYSTEMS=="scsi", KERNELS=="0:0:0:1", SYMLINK+="no-match"
SUBSYSTEMS=="scsi", KERNELS==":0", SYMLINK+="short-id"
SUBSYSTEMS=="scsi", KERNELS=="/0:0:0:0", SYMLINK+="no-match"
SUBSYSTEMS=="scsi", KERNELS=="0:0:0:0", SYMLINK+="scsi-0:0:0:0"
EOF
        },
        {
                desc            => "KERNELS wildcard all",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "scsi-0:0:0:0",
                rules           => <<EOF
SUBSYSTEMS=="scsi", KERNELS=="*:1", SYMLINK+="no-match"
SUBSYSTEMS=="scsi", KERNELS=="*:0:1", SYMLINK+="no-match"
SUBSYSTEMS=="scsi", KERNELS=="*:0:0:1", SYMLINK+="no-match"
SUBSYSTEMS=="scsi", KERNEL=="0:0:0:0", SYMLINK+="before"
SUBSYSTEMS=="scsi", KERNELS=="*", SYMLINK+="scsi-0:0:0:0"
EOF
        },
        {
                desc            => "KERNELS wildcard partial",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "scsi-0:0:0:0",
                rules           => <<EOF
SUBSYSTEMS=="scsi", KERNELS=="0:0:0:0", SYMLINK+="before"
SUBSYSTEMS=="scsi", KERNELS=="*:0", SYMLINK+="scsi-0:0:0:0"
EOF
        },
        {
                desc            => "KERNELS wildcard partial 2",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "scsi-0:0:0:0",
                rules                => <<EOF
SUBSYSTEMS=="scsi", KERNELS=="0:0:0:0", SYMLINK+="before"
SUBSYSTEMS=="scsi", KERNELS=="*:0:0:0", SYMLINK+="scsi-0:0:0:0"
EOF
        },
        {
                desc            => "substitute attr with link target value (first match)",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "driver-is-sd",
                rules           => <<EOF
SUBSYSTEMS=="scsi", SYMLINK+="driver-is-\$attr{driver}"
EOF
        },
        {
                desc            => "substitute attr with link target value (currently selected device)",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "driver-is-ahci",
                rules           => <<EOF
SUBSYSTEMS=="pci", SYMLINK+="driver-is-\$attr{driver}"
EOF
        },
        {
                desc            => "ignore ATTRS attribute whitespace",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "ignored",
                rules           => <<EOF
SUBSYSTEMS=="scsi", ATTRS{whitespace_test}=="WHITE  SPACE", SYMLINK+="ignored"
EOF
        },
        {
                desc            => "do not ignore ATTRS attribute whitespace",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "matched-with-space",
                rules           => <<EOF
SUBSYSTEMS=="scsi", ATTRS{whitespace_test}=="WHITE  SPACE ", SYMLINK+="wrong-to-ignore"
SUBSYSTEMS=="scsi", ATTRS{whitespace_test}=="WHITE  SPACE   ", SYMLINK+="matched-with-space"
EOF
        },
        {
                desc            => "permissions USER=bad GROUP=name",
                devpath         => "/devices/virtual/tty/tty33",
                exp_name        => "tty33",
                exp_perms       => "0:0:0600",
                rules           => <<EOF
KERNEL=="tty33", OWNER="bad", GROUP="name"
EOF
        },
        {
                desc            => "permissions OWNER=1",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "node",
                exp_perms       => "1::0600",
                rules           => <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda", SYMLINK+="node", OWNER="1"
EOF
        },
        {
                desc            => "permissions GROUP=1",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "node",
                exp_perms       => ":1:0660",
                rules           => <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda", SYMLINK+="node", GROUP="1"
EOF
        },
        {
                desc            => "textual user id",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "node",
                exp_perms       => "nobody::0600",
                rules           => <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda", SYMLINK+="node", OWNER="nobody"
EOF
        },
        {
                desc            => "textual group id",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "node",
                exp_perms       => ":daemon:0660",
                rules           => <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda", SYMLINK+="node", GROUP="daemon"
EOF
        },
        {
                desc            => "textual user/group id",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "node",
                exp_perms       => "root:mail:0660",
                rules           => <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda", SYMLINK+="node", OWNER="root", GROUP="mail"
EOF
        },
        {
                desc            => "permissions MODE=0777",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "node",
                exp_perms       => "::0777",
                rules           => <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda", SYMLINK+="node", MODE="0777"
EOF
        },
        {
                desc            => "permissions OWNER=1 GROUP=1 MODE=0777",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "node",
                exp_perms       => "1:1:0777",
                rules           => <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda", SYMLINK+="node", OWNER="1", GROUP="1", MODE="0777"
EOF
        },
        {
                desc            => "permissions OWNER to 1",
                devpath         => "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
                exp_name        => "ttyACM0",
                exp_perms       => "1::",
                rules           => <<EOF
KERNEL=="ttyACM[0-9]*", SYMLINK+="ttyACM%n", OWNER="1"
EOF
        },
        {
                desc            => "permissions GROUP to 1",
                devpath         => "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
                exp_name        => "ttyACM0",
                exp_perms       => ":1:0660",
                rules           => <<EOF
KERNEL=="ttyACM[0-9]*", SYMLINK+="ttyACM%n", GROUP="1"
EOF
        },
        {
                desc            => "permissions MODE to 0060",
                devpath         => "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
                exp_name        => "ttyACM0",
                exp_perms       => "::0060",
                rules           => <<EOF
KERNEL=="ttyACM[0-9]*", SYMLINK+="ttyACM%n", MODE="0060"
EOF
        },
        {
                desc            => "permissions OWNER, GROUP, MODE",
                devpath         => "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
                exp_name        => "ttyACM0",
                exp_perms       => "1:1:0777",
                rules           => <<EOF
KERNEL=="ttyACM[0-9]*", SYMLINK+="ttyACM%n", OWNER="1", GROUP="1", MODE="0777"
EOF
        },
        {
                desc            => "permissions only rule",
                devpath         => "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
                exp_name        => "ttyACM0",
                exp_perms       => "1:1:0777",
                rules           => <<EOF
KERNEL=="ttyACM[0-9]*", OWNER="1", GROUP="1", MODE="0777"
KERNEL=="ttyUSX[0-9]*", OWNER="2", GROUP="2", MODE="0444"
KERNEL=="ttyACM[0-9]*", SYMLINK+="ttyACM%n"
EOF
        },
        {
                desc            => "multiple permissions only rule",
                devpath         => "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
                exp_name        => "ttyACM0",
                exp_perms       => "1:1:0777",
                rules           => <<EOF
SUBSYSTEM=="tty", OWNER="1"
SUBSYSTEM=="tty", GROUP="1"
SUBSYSTEM=="tty", MODE="0777"
KERNEL=="ttyUSX[0-9]*", OWNER="2", GROUP="2", MODE="0444"
KERNEL=="ttyACM[0-9]*", SYMLINK+="ttyACM%n"
EOF
        },
        {
                desc            => "permissions only rule with override at SYMLINK+ rule",
                devpath         => "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
                exp_name        => "ttyACM0",
                exp_perms       => "1:2:0777",
                rules           => <<EOF
SUBSYSTEM=="tty", OWNER="1"
SUBSYSTEM=="tty", GROUP="1"
SUBSYSTEM=="tty", MODE="0777"
KERNEL=="ttyUSX[0-9]*", OWNER="2", GROUP="2", MODE="0444"
KERNEL=="ttyACM[0-9]*", SYMLINK+="ttyACM%n", GROUP="2"
EOF
        },
        {
                desc            => "major/minor number test",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "node",
                exp_majorminor  => "8:0",
                rules           => <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda", SYMLINK+="node"
EOF
        },
        {
                desc            => "big major number test",
                devpath         => "/devices/virtual/misc/misc-fake1",
                exp_name        => "node",
                exp_majorminor  => "4095:1",
                rules                => <<EOF
KERNEL=="misc-fake1", SYMLINK+="node"
EOF
        },
        {
                desc            => "big major and big minor number test",
                devpath         => "/devices/virtual/misc/misc-fake89999",
                exp_name        => "node",
                exp_majorminor  => "4095:89999",
                rules           => <<EOF
KERNEL=="misc-fake89999", SYMLINK+="node"
EOF
        },
        {
                desc            => "multiple symlinks with format char",
                devpath         => "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
                exp_name        => "symlink2-ttyACM0",
                rules           => <<EOF
KERNEL=="ttyACM[0-9]*", SYMLINK="symlink1-%n symlink2-%k symlink3-%b"
EOF
        },
        {
                desc            => "multiple symlinks with a lot of s p a c e s",
                devpath         => "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
                exp_name        => "one",
                not_exp_name        => " ",
                rules           => <<EOF
KERNEL=="ttyACM[0-9]*", SYMLINK="  one     two        "
EOF
        },
        {
                desc            => "symlink creation (same directory)",
                devpath         => "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
                exp_name        => "modem0",
                rules           => <<EOF
KERNEL=="ttyACM[0-9]*", SYMLINK+="ttyACM%n", SYMLINK="modem%n"
EOF
        },
        {
                desc            => "multiple symlinks",
                devpath         => "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
                exp_name        => "second-0" ,
                rules           => <<EOF
KERNEL=="ttyACM0", SYMLINK="first-%n second-%n third-%n"
EOF
        },
        {
                desc            => "symlink name '.'",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => ".",
                exp_add_error        => "yes",
                exp_rem_error        => "yes",
                rules           => <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda", SYMLINK+="."
EOF
        },
        {
                desc            => "symlink node to itself",
                devpath         => "/devices/virtual/tty/tty0",
                exp_name        => "link",
                exp_add_error        => "yes",
                exp_rem_error        => "yes",
                option                => "clean",
                rules           => <<EOF
KERNEL=="tty0", SYMLINK+="tty0"
EOF
        },
        {
                desc            => "symlink %n substitution",
                devpath         => "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
                exp_name        => "symlink0",
                rules           => <<EOF
KERNEL=="ttyACM[0-9]*", SYMLINK+="ttyACM%n", SYMLINK+="symlink%n"
EOF
        },
        {
                desc            => "symlink %k substitution",
                devpath         => "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
                exp_name        => "symlink-ttyACM0",
                rules           => <<EOF
KERNEL=="ttyACM[0-9]*", SYMLINK+="ttyACM%n", SYMLINK+="symlink-%k"
EOF
        },
        {
                desc            => "symlink %M:%m substitution",
                devpath         => "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
                exp_name        => "major-166:0",
                rules           => <<EOF
KERNEL=="ttyACM[0-9]*", SYMLINK+="ttyACM%n", SYMLINK+="major-%M:%m"
EOF
        },
        {
                desc            => "symlink %b substitution",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "symlink-0:0:0:0",
                rules           => <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda", SYMLINK+="symlink-%b"
EOF
        },
        {
                desc            => "symlink %c substitution",
                devpath         => "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
                exp_name        => "test",
                rules           => <<EOF
KERNEL=="ttyACM[0-9]*", PROGRAM=="/bin/echo test", SYMLINK+="%c"
EOF
        },
        {
                desc            => "symlink %c{N} substitution",
                devpath         => "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
                exp_name        => "test",
                rules           => <<EOF
KERNEL=="ttyACM[0-9]*", PROGRAM=="/bin/echo symlink test this", SYMLINK+="%c{2}"
EOF
        },
        {
                desc            => "symlink %c{N+} substitution",
                devpath         => "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
                exp_name        => "this",
                rules           => <<EOF
KERNEL=="ttyACM[0-9]*", PROGRAM=="/bin/echo symlink test this", SYMLINK+="%c{2+}"
EOF
        },
        {
                desc            => "symlink only rule with %c{N+}",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "test",
                rules           => <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda", PROGRAM=="/bin/echo link test this" SYMLINK+="%c{2+}"
EOF
        },
        {
                desc            => "symlink %s{filename} substitution",
                devpath         => "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
                exp_name        => "166:0",
                rules           => <<EOF
KERNEL=="ttyACM[0-9]*", SYMLINK+="%s{dev}"
EOF
        },
        {
                desc            => "program result substitution (numbered part of)",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
                exp_name        => "link1",
                rules           => <<EOF
SUBSYSTEMS=="scsi", PROGRAM=="/bin/echo -n node link1 link2", RESULT=="node *", SYMLINK+="%c{2} %c{3}"
EOF
        },
        {
                desc            => "program result substitution (numbered part of+)",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
                exp_name        => "link4",
                rules           => <<EOF
SUBSYSTEMS=="scsi", PROGRAM=="/bin/echo -n node link1 link2 link3 link4", RESULT=="node *", SYMLINK+="%c{2+}"
EOF
        },
        {
                desc            => "SUBSYSTEM match test",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "node",
                rules           => <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda", SYMLINK+="should_not_match", SUBSYSTEM=="vc"
SUBSYSTEMS=="scsi", KERNEL=="sda", SYMLINK+="node", SUBSYSTEM=="block"
SUBSYSTEMS=="scsi", KERNEL=="sda", SYMLINK+="should_not_match2", SUBSYSTEM=="vc"
EOF
        },
        {
                desc            => "DRIVERS match test",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "node",
                rules           => <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda", SYMLINK+="should_not_match", DRIVERS=="sd-wrong"
SUBSYSTEMS=="scsi", KERNEL=="sda", SYMLINK+="node", DRIVERS=="sd"
EOF
        },
        {
                desc            => "devnode substitution test",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "node",
                rules           => <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda", PROGRAM=="/usr/bin/test -b %N" SYMLINK+="node"
EOF
        },
        {
                desc            => "parent node name substitution test",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
                exp_name        => "sda-part-1",
                rules           => <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda1", SYMLINK+="%P-part-1"
EOF
        },
        {
                desc            => "udev_root substitution",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
                exp_name        => "start-/dev-end",
                rules           => <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda1", SYMLINK+="start-%r-end"
EOF
        },
        {
                desc            => "last_rule option",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
                exp_name        => "last",
                rules           => <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda1", SYMLINK+="last", OPTIONS="last_rule"
SUBSYSTEMS=="scsi", KERNEL=="sda1", SYMLINK+="very-last"
EOF
        },
        {
                desc            => "negation KERNEL!=",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
                exp_name        => "match",
                rules           => <<EOF
SUBSYSTEMS=="scsi", KERNEL!="sda1", SYMLINK+="matches-but-is-negated"
SUBSYSTEMS=="scsi", KERNEL=="sda1", SYMLINK+="before"
SUBSYSTEMS=="scsi", KERNEL!="xsda1", SYMLINK+="match"
EOF
        },
        {
                desc            => "negation SUBSYSTEM!=",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
                exp_name        => "not-anything",
                rules           => <<EOF
SUBSYSTEMS=="scsi", SUBSYSTEM=="block", KERNEL!="sda1", SYMLINK+="matches-but-is-negated"
SUBSYSTEMS=="scsi", KERNEL=="sda1", SYMLINK+="before"
SUBSYSTEMS=="scsi", SUBSYSTEM!="anything", SYMLINK+="not-anything"
EOF
        },
        {
                desc            => "negation PROGRAM!= exit code",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
                exp_name        => "nonzero-program",
                rules           => <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda1", SYMLINK+="before"
KERNEL=="sda1", PROGRAM!="/bin/false", SYMLINK+="nonzero-program"
EOF
        },
        {
                desc            => "ENV{} test",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
                exp_name        => "true",
                rules           => <<EOF
ENV{ENV_KEY_TEST}="test"
SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ENV_KEY_TEST}=="go", SYMLINK+="wrong"
SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ENV_KEY_TEST}=="test", SYMLINK+="true"
SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ENV_KEY_TEST}=="bad", SYMLINK+="bad"
EOF
        },
        {
                desc            => "ENV{} test",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
                exp_name        => "true",
                rules           => <<EOF
ENV{ENV_KEY_TEST}="test"
SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ENV_KEY_TEST}=="go", SYMLINK+="wrong"
SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ENV_KEY_TEST}=="yes", ENV{ACTION}=="add", ENV{DEVPATH}=="*/block/sda/sdax1", SYMLINK+="no"
SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ENV_KEY_TEST}=="test", ENV{ACTION}=="add", ENV{DEVPATH}=="*/block/sda/sda1", SYMLINK+="true"
SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ENV_KEY_TEST}=="bad", SYMLINK+="bad"
EOF
        },
        {
                desc            => "ENV{} test (assign)",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
                exp_name        => "true",
                rules           => <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ASSIGN}="true"
SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ASSIGN}=="yes", SYMLINK+="no"
SUBSYSTEMS=="scsi", KERNEL=="sda1", SYMLINK+="before"
SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ASSIGN}=="true", SYMLINK+="true"
EOF
        },
        {
                desc            => "ENV{} test (assign 2 times)",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
                exp_name        => "true",
                rules           => <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ASSIGN}="true"
SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ASSIGN}="absolutely-\$env{ASSIGN}"
SUBSYSTEMS=="scsi", KERNEL=="sda1", SYMLINK+="before"
SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ASSIGN}=="yes", SYMLINK+="no"
SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ASSIGN}=="absolutely-true", SYMLINK+="true"
EOF
        },
        {
                desc            => "ENV{} test (assign2)",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
                exp_name        => "part",
                rules           => <<EOF
SUBSYSTEM=="block", KERNEL=="*[0-9]", ENV{PARTITION}="true", ENV{MAINDEVICE}="false"
SUBSYSTEM=="block", KERNEL=="*[!0-9]", ENV{PARTITION}="false", ENV{MAINDEVICE}="true"
ENV{MAINDEVICE}=="true", SYMLINK+="disk"
SUBSYSTEM=="block", SYMLINK+="before"
ENV{PARTITION}=="true", SYMLINK+="part"
EOF
        },
        {
                desc            => "untrusted string sanitize",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
                exp_name        => "sane",
                rules           => <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda1", PROGRAM=="/bin/echo -e name; (/usr/bin/badprogram)", RESULT=="name_ _/usr/bin/badprogram_", SYMLINK+="sane"
EOF
        },
        {
                desc            => "untrusted string sanitize (don't replace utf8)",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
                exp_name        => "uber",
                rules           => <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda1", PROGRAM=="/bin/echo -e \\xc3\\xbcber" RESULT=="\xc3\xbcber", SYMLINK+="uber"
EOF
        },
        {
                desc            => "untrusted string sanitize (replace invalid utf8)",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
                exp_name        => "replaced",
                rules           => <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda1", PROGRAM=="/bin/echo -e \\xef\\xe8garbage", RESULT=="__garbage", SYMLINK+="replaced"
EOF
        },
        {
                desc            => "read sysfs value from parent device",
                devpath         => "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
                exp_name        => "serial-354172020305000",
                rules           => <<EOF
KERNEL=="ttyACM*", ATTRS{serial}=="?*", SYMLINK+="serial-%s{serial}"
EOF
        },
        {
                desc            => "match against empty key string",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "ok",
                rules           => <<EOF
KERNEL=="sda", ATTRS{nothing}!="", SYMLINK+="not-1-ok"
KERNEL=="sda", ATTRS{nothing}=="", SYMLINK+="not-2-ok"
KERNEL=="sda", ATTRS{vendor}!="", SYMLINK+="ok"
KERNEL=="sda", ATTRS{vendor}=="", SYMLINK+="not-3-ok"
EOF
        },
        {
                desc            => "check ACTION value",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "ok",
                rules           => <<EOF
ACTION=="unknown", KERNEL=="sda", SYMLINK+="unknown-not-ok"
ACTION=="add", KERNEL=="sda", SYMLINK+="ok"
EOF
        },
        {
                desc            => "final assignment",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "ok",
                exp_perms       => "root:tty:0640",
                rules           => <<EOF
KERNEL=="sda", GROUP:="tty"
KERNEL=="sda", GROUP="not-ok", MODE="0640", SYMLINK+="ok"
EOF
        },
        {
                desc            => "final assignment 2",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "ok",
                exp_perms       => "root:tty:0640",
                rules           => <<EOF
KERNEL=="sda", GROUP:="tty"
SUBSYSTEM=="block", MODE:="640"
KERNEL=="sda", GROUP="not-ok", MODE="0666", SYMLINK+="ok"
EOF
        },
        {
                desc            => "env substitution",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "node-add-me",
                rules           => <<EOF
KERNEL=="sda", MODE="0666", SYMLINK+="node-\$env{ACTION}-me"
EOF
        },
        {
                desc            => "reset list to current value",
                devpath         => "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
                exp_name        => "three",
                not_exp_name    => "two",
                rules           => <<EOF
KERNEL=="ttyACM[0-9]*", SYMLINK+="one"
KERNEL=="ttyACM[0-9]*", SYMLINK+="two"
KERNEL=="ttyACM[0-9]*", SYMLINK="three"
EOF
        },
        {
                desc            => "test empty SYMLINK+ (empty override)",
                devpath         => "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
                exp_name        => "right",
                not_exp_name    => "wrong",
                rules           => <<EOF
KERNEL=="ttyACM[0-9]*", SYMLINK+="wrong"
KERNEL=="ttyACM[0-9]*", SYMLINK=""
KERNEL=="ttyACM[0-9]*", SYMLINK+="right"
EOF
        },
        {
                desc            => "test multi matches",
                devpath         => "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
                exp_name        => "right",
                rules           => <<EOF
KERNEL=="ttyACM*", SYMLINK+="before"
KERNEL=="ttyACM*|nothing", SYMLINK+="right"
EOF
        },
        {
                desc            => "test multi matches 2",
                devpath         => "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
                exp_name        => "right",
                rules           => <<EOF
KERNEL=="dontknow*|*nothing", SYMLINK+="nomatch"
KERNEL=="ttyACM*", SYMLINK+="before"
KERNEL=="dontknow*|ttyACM*|nothing*", SYMLINK+="right"
EOF
        },
        {
                desc            => "test multi matches 3",
                devpath         => "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
                exp_name        => "right",
                rules           => <<EOF
KERNEL=="dontknow|nothing", SYMLINK+="nomatch"
KERNEL=="dontknow|ttyACM0a|nothing|attyACM0", SYMLINK+="wrong1"
KERNEL=="X|attyACM0|dontknow|ttyACM0a|nothing|attyACM0", SYMLINK+="wrong2"
KERNEL=="dontknow|ttyACM0|nothing", SYMLINK+="right"
EOF
        },
        {
                desc            => "test multi matches 4",
                devpath         => "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
                exp_name        => "right",
                rules           => <<EOF
KERNEL=="dontknow|nothing", SYMLINK+="nomatch"
KERNEL=="dontknow|ttyACM0a|nothing|attyACM0", SYMLINK+="wrong1"
KERNEL=="X|attyACM0|dontknow|ttyACM0a|nothing|attyACM0", SYMLINK+="wrong2"
KERNEL=="all|dontknow|ttyACM0", SYMLINK+="right"
KERNEL=="ttyACM0a|nothing", SYMLINK+="wrong3"
EOF
        },
        {
                desc            => "IMPORT parent test sequence 1/2 (keep)",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "parent",
                option          => "keep",
                rules           => <<EOF
KERNEL=="sda", IMPORT{program}="/bin/echo -e \'PARENT_KEY=parent_right\\nWRONG_PARENT_KEY=parent_wrong'"
KERNEL=="sda", SYMLINK+="parent"
EOF
        },
        {
                desc            => "IMPORT parent test sequence 2/2 (keep)",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
                exp_name        => "parentenv-parent_right",
                option          => "clean",
                rules           => <<EOF
KERNEL=="sda1", IMPORT{parent}="PARENT*", SYMLINK+="parentenv-\$env{PARENT_KEY}\$env{WRONG_PARENT_KEY}"
EOF
        },
        {
                desc            => "GOTO test",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
                exp_name        => "right",
                rules           => <<EOF
KERNEL=="sda1", GOTO="TEST"
KERNEL=="sda1", SYMLINK+="wrong"
KERNEL=="sda1", GOTO="BAD"
KERNEL=="sda1", SYMLINK+="", LABEL="NO"
KERNEL=="sda1", SYMLINK+="right", LABEL="TEST", GOTO="end"
KERNEL=="sda1", SYMLINK+="wrong2", LABEL="BAD"
LABEL="end"
EOF
        },
        {
                desc            => "GOTO label does not exist",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
                exp_name        => "right",
                rules           => <<EOF
KERNEL=="sda1", GOTO="does-not-exist"
KERNEL=="sda1", SYMLINK+="right",
LABEL="exists"
EOF
        },
        {
                desc            => "SYMLINK+ compare test",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
                exp_name        => "right",
                not_exp_name    => "wrong",
                rules           => <<EOF
KERNEL=="sda1", SYMLINK+="link"
KERNEL=="sda1", SYMLINK=="link*", SYMLINK+="right"
KERNEL=="sda1", SYMLINK=="nolink*", SYMLINK+="wrong"
EOF
        },
        {
                desc            => "invalid key operation",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
                exp_name        => "yes",
                rules           => <<EOF
KERNEL="sda1", SYMLINK+="no"
KERNEL=="sda1", SYMLINK+="yes"
EOF
        },
        {
                desc            => "operator chars in attribute",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "yes",
                rules           => <<EOF
KERNEL=="sda", ATTR{test:colon+plus}=="?*", SYMLINK+="yes"
EOF
        },
        {
                desc            => "overlong comment line",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
                exp_name        => "yes",
                rules           => <<EOF
# 012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789
   # 012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789
KERNEL=="sda1", SYMLINK+=="no"
KERNEL=="sda1", SYMLINK+="yes"
EOF
        },
        {
                desc            => "magic subsys/kernel lookup",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "00:16:41:e2:8d:ff",
                rules           => <<EOF
KERNEL=="sda", SYMLINK+="\$attr{[net/eth0]address}"
EOF
        },
        {
                desc            => "TEST absolute path",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "there",
                rules           => <<EOF
TEST=="/etc/machine-id", SYMLINK+="there"
TEST!="/etc/machine-id", SYMLINK+="notthere"
EOF
        },
        {
                desc            => "TEST subsys/kernel lookup",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "yes",
                rules           => <<EOF
KERNEL=="sda", TEST=="[net/eth0]", SYMLINK+="yes"
EOF
        },
        {
                desc            => "TEST relative path",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "relative",
                rules           => <<EOF
KERNEL=="sda", TEST=="size", SYMLINK+="relative"
EOF
        },
        {
                desc            => "TEST wildcard substitution (find queue/nr_requests)",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "found-subdir",
                rules           => <<EOF
KERNEL=="sda", TEST=="*/nr_requests", SYMLINK+="found-subdir"
EOF
        },
        {
                desc            => "TEST MODE=0000",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "sda",
                exp_perms       => "0:0:0000",
                exp_rem_error   => "yes",
                rules           => <<EOF
KERNEL=="sda", MODE="0000"
EOF
        },
        {
                desc            => "TEST PROGRAM feeds OWNER, GROUP, MODE",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "sda",
                exp_perms       => "1:1:0400",
                exp_rem_error   => "yes",
                rules           => <<EOF
KERNEL=="sda", MODE="666"
KERNEL=="sda", PROGRAM=="/bin/echo 1 1 0400", OWNER="%c{1}", GROUP="%c{2}", MODE="%c{3}"
EOF
        },
        {
                desc            => "TEST PROGRAM feeds MODE with overflow",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "sda",
                exp_perms       => "0:0:0440",
                exp_rem_error   => "yes",
                rules           => <<EOF
KERNEL=="sda", MODE="440"
KERNEL=="sda", PROGRAM=="/bin/echo 0 0 0400letsdoabuffferoverflow0123456789012345789012345678901234567890", OWNER="%c{1}", GROUP="%c{2}", MODE="%c{3}"
EOF
        },
        {
                desc            => "magic [subsys/sysname] attribute substitution",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "sda-8741C4G-end",
                exp_perms       => "0:0:0600",
                rules           => <<EOF
KERNEL=="sda", PROGRAM="/bin/true create-envp"
KERNEL=="sda", ENV{TESTENV}="change-envp"
KERNEL=="sda", SYMLINK+="%k-%s{[dmi/id]product_name}-end"
EOF
        },
        {
                desc            => "builtin path_id",
                devpath         => "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
                exp_name        => "disk/by-path/pci-0000:00:1f.2-scsi-0:0:0:0",
                rules           => <<EOF
KERNEL=="sda", IMPORT{builtin}="path_id"
KERNEL=="sda", ENV{ID_PATH}=="?*", SYMLINK+="disk/by-path/\$env{ID_PATH}"
EOF
        },
);

sub udev {
        my ($action, $devpath, $rules) = @_;

        # create temporary rules
        system("mkdir", "-p", "$udev_rules_dir");
        open CONF, ">$udev_rules" || die "unable to create rules file: $udev_rules";
        print CONF $$rules;
        close CONF;

        if ($valgrind > 0) {
                system("$udev_bin_valgrind $action $devpath");
        } elsif ($gdb > 0) {
                system("$udev_bin_gdb $action $devpath");
        } else {
                system("$udev_bin", "$action", "$devpath");
        }
}

my $error = 0;

sub permissions_test {
        my($rules, $uid, $gid, $mode) = @_;

        my $wrong = 0;
        my $userid;
        my $groupid;

        $rules->{exp_perms} =~ m/^(.*):(.*):(.*)$/;
        if ($1 ne "") {
                if (defined(getpwnam($1))) {
                        $userid = int(getpwnam($1));
                } else {
                        $userid = $1;
                }
                if ($uid != $userid) { $wrong = 1; }
        }
        if ($2 ne "") {
                if (defined(getgrnam($2))) {
                        $groupid = int(getgrnam($2));
                } else {
                        $groupid = $2;
                }
                if ($gid != $groupid) { $wrong = 1; }
        }
        if ($3 ne "") {
                if (($mode & 07777) != oct($3)) { $wrong = 1; };
        }
        if ($wrong == 0) {
                print "permissions: ok\n";
        } else {
                printf "  expected permissions are: %s:%s:%#o\n", $1, $2, oct($3);
                printf "  created permissions are : %i:%i:%#o\n", $uid, $gid, $mode & 07777;
                print "permissions: error\n";
                $error++;
                sleep(1);
        }
}

sub major_minor_test {
        my($rules, $rdev) = @_;

        my $major = ($rdev >> 8) & 0xfff;
        my $minor = ($rdev & 0xff) | (($rdev >> 12) & 0xfff00);
        my $wrong = 0;

        $rules->{exp_majorminor} =~ m/^(.*):(.*)$/;
        if ($1 ne "") {
                if ($major != $1) { $wrong = 1; };
        }
        if ($2 ne "") {
                if ($minor != $2) { $wrong = 1; };
        }
        if ($wrong == 0) {
                print "major:minor: ok\n";
        } else {
                printf "  expected major:minor is: %i:%i\n", $1, $2;
                printf "  created major:minor is : %i:%i\n", $major, $minor;
                print "major:minor: error\n";
                $error++;
                sleep(1);
        }
}

sub udev_setup {
        system("rm", "-rf", "$udev_dev");
        mkdir($udev_dev) || die "unable to create udev_dev: $udev_dev\n";
        # setting group and mode of udev_dev ensures the tests work
        # even if the parent directory has setgid bit enabled.
        chown (0, 0, $udev_dev) || die "unable to chown $udev_dev\n";
        chmod (0755, $udev_dev) || die "unable to chmod $udev_dev\n";

        system("rm", "-rf", "$udev_run");
}

sub run_test {
        my ($rules, $number) = @_;

        print "TEST $number: $rules->{desc}\n";
        print "device \'$rules->{devpath}\' expecting node/link \'$rules->{exp_name}\'\n";

        udev("add", $rules->{devpath}, \$rules->{rules});
        if (defined($rules->{not_exp_name})) {
                if ((-e "$udev_dev/$rules->{not_exp_name}") ||
                    (-l "$udev_dev/$rules->{not_exp_name}")) {
                        print "nonexistent: error \'$rules->{not_exp_name}\' not expected to be there\n";
                        $error++;
                        sleep(1);
                }
        }

        if ((-e "$udev_dev/$rules->{exp_name}") ||
            (-l "$udev_dev/$rules->{exp_name}")) {

                my ($dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size,
                    $atime, $mtime, $ctime, $blksize, $blocks) = stat("$udev_dev/$rules->{exp_name}");

                if (defined($rules->{exp_perms})) {
                        permissions_test($rules, $uid, $gid, $mode);
                }
                if (defined($rules->{exp_majorminor})) {
                        major_minor_test($rules, $rdev);
                }
                print "add:         ok\n";
        } else {
                print "add:         error";
                if ($rules->{exp_add_error}) {
                        print " as expected\n";
                } else {
                        print "\n";
                        system("tree", "$udev_dev");
                        print "\n";
                        $error++;
                        sleep(1);
                }
        }

        if (defined($rules->{option}) && $rules->{option} eq "keep") {
                print "\n\n";
                return;
        }

        udev("remove", $rules->{devpath}, \$rules->{rules});
        if ((-e "$udev_dev/$rules->{exp_name}") ||
            (-l "$udev_dev/$rules->{exp_name}")) {
                print "remove:      error";
                if ($rules->{exp_rem_error}) {
                        print " as expected\n";
                } else {
                        print "\n";
                        system("tree", "$udev_dev");
                        print "\n";
                        $error++;
                        sleep(1);
                }
        } else {
                print "remove:      ok\n";
        }

        print "\n";

        if (defined($rules->{option}) && $rules->{option} eq "clean") {
                udev_setup();
        }

}

# only run if we have root permissions
# due to mknod restrictions
if (!($<==0)) {
        print "Must have root permissions to run properly.\n";
        exit($EXIT_TEST_SKIP);
}

# skip the test when running in a container
system("systemd-detect-virt", "-c", "-q");
if ($? >> 8 == 0) {
    print "Running in a container, skipping the test.\n";
    exit($EXIT_TEST_SKIP);
}

udev_setup();

my $test_num = 1;
my @list;

foreach my $arg (@ARGV) {
        if ($arg =~ m/--valgrind/) {
                $valgrind = 1;
                printf("using valgrind\n");
        } elsif ($arg =~ m/--gdb/) {
                $gdb = 1;
                printf("using gdb\n");
        } else {
                push(@list, $arg);
        }
}

if ($list[0]) {
        foreach my $arg (@list) {
                if (defined($tests[$arg-1]->{desc})) {
                        print "udev-test will run test number $arg:\n\n";
                        run_test($tests[$arg-1], $arg);
                } else {
                        print "test does not exist.\n";
                }
        }
} else {
        # test all
        print "\nudev-test will run ".($#tests + 1)." tests:\n\n";

        foreach my $rules (@tests) {
                run_test($rules, $test_num);
                $test_num++;
        }
}

print "$error errors occurred\n\n";

# cleanup
system("rm", "-rf", "$udev_dev");
system("rm", "-rf", "$udev_run");

if ($error > 0) {
    exit(1);
}
exit(0);
