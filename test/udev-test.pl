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
# Copyright (C) 2004-2008 Kay Sievers <kay.sievers@vrfy.org>
# Copyright (C) 2004 Leann Ogasawara <ogasawara@osdl.org>

use warnings;
use strict;

my $PWD			= $ENV{PWD};
my $sysfs		= "sys/";
my $udev_bin		= "../udev/test-udev";
my $valgrind		= 0;
my $udev_bin_valgrind	= "valgrind --tool=memcheck --leak-check=yes --quiet $udev_bin";
my $udev_root		= "udev-root/";
my $udev_conf		= "udev-test.conf";
my $udev_rules		= "udev-test.rules";

my @tests = (
	{
		desc		=> "no rules",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "sda" ,
		rules		=> <<EOF
EOF
	},
	{
		desc		=> "label test of scsi disc (old key names)",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "boot_disk" ,
		rules		=> <<EOF
SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", NAME="boot_disk%n", RUN+="socket:@/org/kernel/udev/monitor"
KERNEL=="ttyACM0", NAME="modem"
EOF
	},
	{
		desc		=> "label test of scsi disc (old key names)",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "boot_disk" ,
		rules		=> <<EOF
SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", NAME="boot_disk%n"
KERNEL=="ttyACM0", NAME="modem"
EOF
	},
	{
		desc		=> "label test of scsi disc",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "boot_disk" ,
		rules		=> <<EOF
SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", NAME="boot_disk%n"
KERNEL=="ttyACM0", NAME="modem"
EOF
	},
	{
		desc		=> "label test of scsi partition",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
		exp_name	=> "boot_disk1" ,
		rules		=> <<EOF
SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", NAME="boot_disk%n"
EOF
	},
	{
		desc		=> "label test of pattern match",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
		exp_name	=> "boot_disk1" ,
		rules		=> <<EOF
SUBSYSTEMS=="scsi", ATTRS{vendor}=="?ATA", NAME="boot_disk%n-1"
SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA?", NAME="boot_disk%n-2"
SUBSYSTEMS=="scsi", ATTRS{vendor}=="A??", NAME="boot_disk%n"
SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATAS", NAME="boot_disk%n-3"
EOF
	},
	{
		desc		=> "label test of multiple sysfs files",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
		exp_name	=> "boot_disk1" ,
		rules		=> <<EOF
SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", ATTRS{model}=="ST910021AS X ", NAME="boot_diskX%n"
SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", ATTRS{model}=="ST910021AS", NAME="boot_disk%n"
EOF
	},
	{
		desc		=> "label test of max sysfs files (skip invalid rule)",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
		exp_name	=> "boot_disk1" ,
		rules		=> <<EOF
SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", ATTRS{model}=="ST910021AS", ATTRS{scsi_level}=="6", ATTRS{rev}=="4.06", ATTRS{type}=="0", ATTRS{queue_depth}=="32", NAME="boot_diskXX%n"
SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", ATTRS{model}=="ST910021AS", ATTRS{scsi_level}=="6", ATTRS{rev}=="4.06", ATTRS{type}=="0", NAME="boot_disk%n"
EOF
	},
	{
		desc		=> "catch device by *",
		subsys		=> "tty",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "modem/0" ,
		rules		=> <<EOF
KERNEL=="ttyACM*", NAME="modem/%n"
EOF
	},
	{
		desc		=> "catch device by * - take 2",
		subsys		=> "tty",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "modem/0" ,
		rules		=> <<EOF
KERNEL=="*ACM1", NAME="bad"
KERNEL=="*ACM0", NAME="modem/%n"
EOF
	},
	{
		desc		=> "catch device by ?",
		subsys		=> "tty",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "modem/0" ,
		rules		=> <<EOF
KERNEL=="ttyACM??*", NAME="modem/%n-1"
KERNEL=="ttyACM??", NAME="modem/%n-2"
KERNEL=="ttyACM?", NAME="modem/%n"
EOF
	},
	{
		desc		=> "catch device by character class",
		subsys		=> "tty",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "modem/0" ,
		rules		=> <<EOF
KERNEL=="ttyACM[A-Z]*", NAME="modem/%n-1"
KERNEL=="ttyACM?[0-9]", NAME="modem/%n-2"
KERNEL=="ttyACM[0-9]*", NAME="modem/%n"
EOF
	},
	{
		desc		=> "replace kernel name",
		subsys		=> "tty",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "modem" ,
		rules		=> <<EOF
KERNEL=="ttyACM0", NAME="modem"
EOF
	},
	{
		desc		=> "Handle comment lines in config file (and replace kernel name)",
		subsys		=> "tty",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "modem" ,
		rules		=> <<EOF
# this is a comment
KERNEL=="ttyACM0", NAME="modem"

EOF
	},
	{
		desc		=> "Handle comment lines in config file with whitespace (and replace kernel name)",
		subsys		=> "tty",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "modem" ,
		rules		=> <<EOF
 # this is a comment with whitespace before the comment 
KERNEL=="ttyACM0", NAME="modem"

EOF
	},
	{
		desc		=> "Handle whitespace only lines (and replace kernel name)",
		subsys		=> "tty",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "whitespace" ,
		rules		=> <<EOF

 

 # this is a comment with whitespace before the comment 
KERNEL=="ttyACM0", NAME="whitespace"

 

EOF
	},
	{
		desc		=> "Handle empty lines in config file (and replace kernel name)",
		subsys		=> "tty",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "modem" ,
		rules		=> <<EOF

KERNEL=="ttyACM0", NAME="modem"

EOF
	},
	{
		desc		=> "Handle backslashed multi lines in config file (and replace kernel name)",
		subsys		=> "tty",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "modem" ,
		rules		=> <<EOF
KERNEL=="ttyACM0", \\
NAME="modem"

EOF
	},
	{
		desc		=> "preserve backslashes, if they are not for a newline",
		subsys		=> "tty",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "aaa",
		rules		=> <<EOF
KERNEL=="ttyACM0", PROGRAM=="/bin/echo -e \\101", RESULT=="A", NAME="aaa"
EOF
	},
	{
		desc		=> "Handle stupid backslashed multi lines in config file (and replace kernel name)",
		subsys		=> "tty",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "modem" ,
		rules		=> <<EOF

#
\\

\\

#\\

KERNEL=="ttyACM0", \\
	NAME="modem"

EOF
	},
	{
		desc		=> "subdirectory handling",
		subsys		=> "tty",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "sub/direct/ory/modem" ,
		rules		=> <<EOF
KERNEL=="ttyACM0", NAME="sub/direct/ory/modem"
EOF
	},
	{
		desc		=> "parent device name match of scsi partition",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
		exp_name	=> "first_disk5" ,
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNELS=="0:0:0:0", NAME="first_disk%n"
EOF
	},
	{
		desc		=> "test substitution chars (old key names)",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
		exp_name	=> "Major:8:minor:5:kernelnumber:5:id:0:0:0:0" ,
		rules		=> <<EOF
BUS=="scsi", ID=="0:0:0:0", NAME="Major:%M:minor:%m:kernelnumber:%n:id:%b"
EOF
	},
	{
		desc		=> "test substitution chars",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
		exp_name	=> "Major:8:minor:5:kernelnumber:5:id:0:0:0:0" ,
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNELS=="0:0:0:0", NAME="Major:%M:minor:%m:kernelnumber:%n:id:%b"
EOF
	},
	{
		desc		=> "test substitution chars (with length limit)",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
		exp_name	=> "M8-m5-n5-b0:0-xAT" ,
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNELS=="0:0:0:0", NAME="M%M-m%m-n%n-b%3b-x%2s{vendor}"
EOF
	},
	{
		desc		=> "import of shell-value file",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "subdir/err/node" ,
		rules		=> <<EOF
SUBSYSTEMS=="scsi", IMPORT{file}="udev-test.conf", NAME="subdir/%E{udev_log}/node"
KERNEL=="ttyACM0", NAME="modem"
EOF
	},
	{
		desc		=> "import of shell-value returned from program",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "node12345678",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", IMPORT="/bin/echo -e \' TEST_KEY=12345678\\n  TEST_key2=98765\'", NAME="node\$env{TEST_KEY}"
KERNEL=="ttyACM0", NAME="modem"
EOF
	},
	{
		desc		=> "sustitution of sysfs value (%s{file})",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "disk-ATA-sda" ,
		rules		=> <<EOF
SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", NAME="disk-%s{vendor}-%k"
KERNEL=="ttyACM0", NAME="modem"
EOF
	},
	{
		desc		=> "program result substitution",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
		exp_name	=> "special-device-5" ,
		rules		=> <<EOF
SUBSYSTEMS=="scsi", PROGRAM=="/bin/echo -n special-device", RESULT=="-special-*", NAME="%c-1-%n"
SUBSYSTEMS=="scsi", PROGRAM=="/bin/echo -n special-device", RESULT=="special--*", NAME="%c-2-%n"
SUBSYSTEMS=="scsi", PROGRAM=="/bin/echo -n special-device", RESULT=="special-device-", NAME="%c-3-%n"
SUBSYSTEMS=="scsi", PROGRAM=="/bin/echo -n special-device", RESULT=="special-devic", NAME="%c-4-%n"
SUBSYSTEMS=="scsi", PROGRAM=="/bin/echo -n special-device", RESULT=="special-*", NAME="%c-%n"
EOF
	},
	{
		desc		=> "program result substitution (newline removal)",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
		exp_name	=> "newline_removed" ,
		rules		=> <<EOF
SUBSYSTEMS=="scsi", PROGRAM=="/bin/echo test", RESULT=="test", NAME="newline_removed"
EOF
	},
	{
		desc		=> "program result substitution",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
		exp_name	=> "test-0:0:0:0" ,
		rules		=> <<EOF
SUBSYSTEMS=="scsi", PROGRAM=="/bin/echo -n test-%b", RESULT=="test-0:0*", NAME="%c"
EOF
	},
	{
		desc		=> "program with escaped format char (tricky: callout returns format char!)",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
		exp_name	=> "escape-5" ,
		rules		=> <<EOF
SUBSYSTEMS=="scsi", PROGRAM=="/bin/echo -n escape-%%n", KERNEL=="sda5", NAME="%c"
EOF
	},
	{
		desc		=> "program with lots of arguments",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
		exp_name	=> "foo9" ,
		rules		=> <<EOF
SUBSYSTEMS=="scsi", PROGRAM=="/bin/echo -n foo3 foo4 foo5 foo6 foo7 foo8 foo9", KERNEL=="sda5", NAME="%c{7}"
EOF
	},
	{
		desc		=> "program with subshell",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
		exp_name	=> "bar9" ,
		rules		=> <<EOF
SUBSYSTEMS=="scsi", PROGRAM=="/bin/sh -c 'echo foo3 foo4 foo5 foo6 foo7 foo8 foo9 | sed  s/foo9/bar9/'", KERNEL=="sda5", NAME="%c{7}"
EOF
	},
	{
		desc		=> "program arguments combined with apostrophes",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
		exp_name	=> "foo7" ,
		rules		=> <<EOF
SUBSYSTEMS=="scsi", PROGRAM=="/bin/echo -n 'foo3 foo4'   'foo5   foo6   foo7 foo8'", KERNEL=="sda5", NAME="%c{5}"
EOF
	},
	{
		desc		=> "characters before the %c{N} substitution",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
		exp_name	=> "my-foo9" ,
		rules		=> <<EOF
SUBSYSTEMS=="scsi", PROGRAM=="/bin/echo -n foo3 foo4 foo5 foo6 foo7 foo8 foo9", KERNEL=="sda5", NAME="my-%c{7}"
EOF
	},
	{
		desc		=> "substitute the second to last argument",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
		exp_name	=> "my-foo8" ,
		rules		=> <<EOF
SUBSYSTEMS=="scsi", PROGRAM=="/bin/echo -n foo3 foo4 foo5 foo6 foo7 foo8 foo9", KERNEL=="sda5", NAME="my-%c{6}"
EOF
	},
	{
		desc		=> "test substitution by variable name",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
		exp_name	=> "Major:8-minor:5-kernelnumber:5-id:0:0:0:0",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNELS=="0:0:0:0", NAME="Major:\$major-minor:\$minor-kernelnumber:\$number-id:\$id"
EOF
	},
	{
		desc		=> "test substitution by variable name 2",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
		exp_name	=> "Major:8-minor:5-kernelnumber:5-id:0:0:0:0",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNELS=="0:0:0:0", DEVPATH=="*/sda/*", NAME="Major:\$major-minor:%m-kernelnumber:\$number-id:\$id"
EOF
	},
	{
		desc		=> "test substitution by variable name 3",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
		exp_name	=> "850:0:0:05" ,
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNELS=="0:0:0:0", DEVPATH=="*/sda/*", NAME="%M%m%b%n"
EOF
	},
	{
		desc		=> "test substitution by variable name 4",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
		exp_name	=> "855" ,
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNELS=="0:0:0:0", DEVPATH=="*/sda/*", NAME="\$major\$minor\$number"
EOF
	},
	{
		desc		=> "test substitution by variable name 5",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
		exp_name	=> "8550:0:0:0" ,
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNELS=="0:0:0:0", DEVPATH=="*/sda/*", NAME="\$major%m%n\$id"
EOF
	},
	{
		desc		=> "non matching SUBSYSTEMS for device with no parent",
		subsys		=> "tty",
		devpath		=> "/devices/virtual/tty/console",
		exp_name	=> "TTY",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", PROGRAM=="/bin/echo -n foo", RESULT=="foo", NAME="foo"
KERNEL=="console", NAME="TTY"
EOF
	},
	{
		desc		=> "non matching SUBSYSTEMS",
		subsys		=> "tty",
		devpath		=> "/devices/virtual/tty/console",
		exp_name	=> "TTY" ,
		rules		=> <<EOF
SUBSYSTEMS=="foo", ATTRS{dev}=="5:1", NAME="foo"
KERNEL=="console", NAME="TTY"
EOF
	},
	{
		desc		=> "ATTRS match",
		subsys		=> "tty",
		devpath		=> "/devices/virtual/tty/console",
		exp_name	=> "foo" ,
		rules		=> <<EOF
KERNEL=="console", NAME="TTY"
ATTRS{dev}=="5:1", NAME="foo"
EOF
	},
	{
		desc		=> "program and bus type match",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "scsi-0:0:0:0" ,
		rules		=> <<EOF
SUBSYSTEMS=="usb", PROGRAM=="/bin/echo -n usb-%b", NAME="%c"
SUBSYSTEMS=="scsi", PROGRAM=="/bin/echo -n scsi-%b", NAME="%c"
SUBSYSTEMS=="foo", PROGRAM=="/bin/echo -n foo-%b", NAME="%c"
EOF
	},
	{
		desc		=> "create all possible partitions",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "boot_disk15" ,
		exp_majorminor	=> "8:15",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", NAME{all_partitions}="boot_disk"
EOF
	},
	{
		desc		=> "sysfs parent hierarchy",
		subsys		=> "tty",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "modem" ,
		rules		=> <<EOF
ATTRS{idProduct}=="007b", NAME="modem"
EOF
	},
	{
		desc		=> "name test with ! in the name",
		subsys		=> "block",
		devpath		=> "/devices/virtual/block/fake!blockdev0",
		exp_name	=> "is/a/fake/blockdev0" ,
		rules		=> <<EOF
SUBSYSTEMS=="scsi", NAME="is/not/a/%k"
SUBSYSTEM=="block", NAME="is/a/%k"
KERNEL=="ttyACM0", NAME="modem"
EOF
	},
	{
		desc		=> "name test with ! in the name, but no matching rule",
		subsys		=> "block",
		devpath		=> "/devices/virtual/block/fake!blockdev0",
		exp_name	=> "fake/blockdev0" ,
		rules		=> <<EOF
KERNEL=="ttyACM0", NAME="modem"
EOF
	},
	{
		desc		=> "KERNELS rule",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "scsi-0:0:0:0",
		rules		=> <<EOF
SUBSYSTEMS=="usb", KERNELS=="0:0:0:0", NAME="not-scsi"
SUBSYSTEMS=="scsi", KERNELS=="0:0:0:1", NAME="no-match"
SUBSYSTEMS=="scsi", KERNELS==":0", NAME="short-id"
SUBSYSTEMS=="scsi", KERNELS=="/0:0:0:0", NAME="no-match"
SUBSYSTEMS=="scsi", KERNELS=="0:0:0:0", NAME="scsi-0:0:0:0"
EOF
	},
	{
		desc		=> "KERNELS wildcard all",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "scsi-0:0:0:0",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNELS=="*:1", NAME="no-match"
SUBSYSTEMS=="scsi", KERNELS=="*:0:1", NAME="no-match"
SUBSYSTEMS=="scsi", KERNELS=="*:0:0:1", NAME="no-match"
SUBSYSTEMS=="scsi", KERNEL=="0:0:0:0", NAME="before"
SUBSYSTEMS=="scsi", KERNELS=="*", NAME="scsi-0:0:0:0"
EOF
	},
	{
		desc		=> "KERNELS wildcard partial",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "scsi-0:0:0:0",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNELS=="0:0:0:0", NAME="before"
SUBSYSTEMS=="scsi", KERNELS=="*:0", NAME="scsi-0:0:0:0"
EOF
	},
	{
		desc		=> "KERNELS wildcard partial 2",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "scsi-0:0:0:0",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNELS=="0:0:0:0", NAME="before"
SUBSYSTEMS=="scsi", KERNELS=="*:0:0:0", NAME="scsi-0:0:0:0"
EOF
	},
	{
		desc		=> "substitute attr with link target value (first match)",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "driver-is-sd",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", NAME="driver-is-\$attr{driver}"
EOF
	},
	{
		desc		=> "substitute attr with link target value (currently selected device)",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "driver-is-ahci",
		rules		=> <<EOF
SUBSYSTEMS=="pci", NAME="driver-is-\$attr{driver}"
EOF
	},
	{
		desc		=> "ignore ATTRS attribute whitespace",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "ignored",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", ATTRS{whitespace_test}=="WHITE  SPACE", NAME="ignored"
EOF
	},
	{
		desc		=> "do not ignore ATTRS attribute whitespace",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "matched-with-space",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", ATTRS{whitespace_test}=="WHITE  SPACE ", NAME="wrong-to-ignore"
SUBSYSTEMS=="scsi", ATTRS{whitespace_test}=="WHITE  SPACE   ", NAME="matched-with-space"
EOF
	},
	{
		desc		=> "permissions USER=bad GROUP=name",
		subsys		=> "tty",
		devpath		=> "/devices/virtual/tty/tty33",
		exp_name	=> "tty33",
		exp_perms	=> "0:0:0660",
		rules		=> <<EOF
KERNEL=="tty33", NAME="tty33", OWNER="bad", GROUP="name"
EOF
	},
	{
		desc		=> "permissions OWNER=5000",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "node",
		exp_perms	=> "5000::0660",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda", NAME="node", OWNER="5000"
EOF
	},
	{
		desc		=> "permissions GROUP=100",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "node",
		exp_perms	=> ":100:0660",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda", NAME="node", GROUP="100"
EOF
	},
	{
		desc		=> "textual user id",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "node",
		exp_perms	=> "nobody::0660",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda", NAME="node", OWNER="nobody"
EOF
	},
	{
		desc		=> "textual group id",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "node",
		exp_perms	=> ":daemon:0660",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda", NAME="node", GROUP="daemon"
EOF
	},
	{
		desc		=> "textual user/group id",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "node",
		exp_perms	=> "root:mail:0660",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda", NAME="node", OWNER="root", GROUP="mail"
EOF
	},
	{
		desc		=> "permissions MODE=0777",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "node",
		exp_perms	=> "::0777",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda", NAME="node", MODE="0777"
EOF
	},
	{
		desc		=> "permissions OWNER=5000 GROUP=100 MODE=0777",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "node",
		exp_perms	=> "5000:100:0777",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda", NAME="node", OWNER="5000", GROUP="100", MODE="0777"
EOF
	},
	{
		desc		=> "permissions OWNER to 5000",
		subsys		=> "tty",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "ttyACM0",
		exp_perms	=> "5000::",
		rules		=> <<EOF
KERNEL=="ttyACM[0-9]*", NAME="ttyACM%n", OWNER="5000"
EOF
	},
	{
		desc		=> "permissions GROUP to 100",
		subsys		=> "tty",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "ttyACM0",
		exp_perms	=> ":100:0660",
		rules		=> <<EOF
KERNEL=="ttyACM[0-9]*", NAME="ttyACM%n", GROUP="100"
EOF
	},
	{
		desc		=> "permissions MODE to 0060",
		subsys		=> "tty",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "ttyACM0",
		exp_perms	=> "::0060",
		rules		=> <<EOF
KERNEL=="ttyACM[0-9]*", NAME="ttyACM%n", MODE="0060"
EOF
	},
	{
		desc		=> "permissions OWNER, GROUP, MODE",
		subsys		=> "tty",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "ttyACM0",
		exp_perms	=> "5000:100:0777",
		rules		=> <<EOF
KERNEL=="ttyACM[0-9]*", NAME="ttyACM%n", OWNER="5000", GROUP="100", MODE="0777"
EOF
	},
	{
		desc		=> "permissions only rule",
		subsys		=> "tty",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "ttyACM0",
		exp_perms	=> "5000:100:0777",
		rules		=> <<EOF
KERNEL=="ttyACM[0-9]*", OWNER="5000", GROUP="100", MODE="0777"
KERNEL=="ttyUSX[0-9]*", OWNER="5001", GROUP="101", MODE="0444"
KERNEL=="ttyACM[0-9]*", NAME="ttyACM%n"
EOF
	},
	{
		desc		=> "multiple permissions only rule",
		subsys		=> "tty",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "ttyACM0",
		exp_perms	=> "3000:4000:0777",
		rules		=> <<EOF
SUBSYSTEM=="tty", OWNER="3000"
SUBSYSTEM=="tty", GROUP="4000"
SUBSYSTEM=="tty", MODE="0777"
KERNEL=="ttyUSX[0-9]*", OWNER="5001", GROUP="101", MODE="0444"
KERNEL=="ttyACM[0-9]*", NAME="ttyACM%n"
EOF
	},
	{
		desc		=> "permissions only rule with override at NAME rule",
		subsys		=> "tty",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "ttyACM0",
		exp_perms	=> "3000:8000:0777",
		rules		=> <<EOF
SUBSYSTEM=="tty", OWNER="3000"
SUBSYSTEM=="tty", GROUP="4000"
SUBSYSTEM=="tty", MODE="0777"
KERNEL=="ttyUSX[0-9]*", OWNER="5001", GROUP="101", MODE="0444"
KERNEL=="ttyACM[0-9]*", NAME="ttyACM%n", GROUP="8000"
EOF
	},
	{
		desc		=> "major/minor number test",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "node",
		exp_majorminor	=> "8:0",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda", NAME="node"
EOF
	},
	{
		desc		=> "big major number test",
		subsys		=> "misc",
		devpath		=> "/devices/virtual/misc/misc-fake1",
		exp_name	=> "node",
		exp_majorminor	=> "4095:1",
		rules		=> <<EOF
KERNEL=="misc-fake1", NAME="node"
EOF
	},
	{
		desc		=> "big major and big minor number test",
		subsys		=> "misc",
		devpath		=> "/devices/virtual/misc/misc-fake89999",
		exp_name	=> "node",
		exp_majorminor	=> "4095:89999",
		rules		=> <<EOF
KERNEL=="misc-fake89999", NAME="node"
EOF
	},
	{
		desc		=> "multiple symlinks with format char",
		subsys		=> "tty",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "symlink2-ttyACM0",
		exp_target	=> "ttyACM0",
		rules		=> <<EOF
KERNEL=="ttyACM[0-9]*", NAME="ttyACM%n", SYMLINK="symlink1-%n symlink2-%k symlink3-%b"
EOF
	},
	{
		desc		=> "multiple symlinks with a lot of s p a c e s",
		subsys		=> "tty",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "one",
		not_exp_name	=> " ",
		exp_target	=> "ttyACM0",
		rules		=> <<EOF
KERNEL=="ttyACM[0-9]*", NAME="ttyACM%n", SYMLINK="  one     two        "
EOF
	},
	{
		desc		=> "symlink creation (same directory)",
		subsys		=> "tty",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "modem0",
		exp_target	=> "ttyACM0",
		rules		=> <<EOF
KERNEL=="ttyACM[0-9]*", NAME="ttyACM%n", SYMLINK="modem%n"
EOF
	},
	{
		desc		=> "symlink creation (relative link forward)",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda6",
		exp_name	=> "1/2/symlink" ,
		exp_target	=> "a/b/node",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", NAME="1/2/a/b/node", SYMLINK="1/2/symlink"
EOF
	},
	{
		desc		=> "symlink creation (relative link back and forward)",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda6",
		exp_name	=> "1/2/c/d/symlink" ,
		exp_target	=> "../../a/b/node",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA", NAME="1/2/a/b/node", SYMLINK="1/2/c/d/symlink"
EOF
	},
	{
		desc		=> "multiple symlinks",
		subsys		=> "tty",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "second-0" ,
		exp_target	=> "modem" ,
		rules		=> <<EOF
KERNEL=="ttyACM0", NAME="modem", SYMLINK="first-%n second-%n third-%n"
EOF
	},
	{
		desc		=> "symlink only rule",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "symlink-only2",
		exp_target	=> "link",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda", SYMLINK+="symlink-only1"
SUBSYSTEMS=="scsi", KERNEL=="sda", SYMLINK+="symlink-only2"
SUBSYSTEMS=="scsi", KERNEL=="sda", NAME="link", SYMLINK+="symlink0"
EOF
	},
	{
		desc		=> "symlink name '.'",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> ".",
		exp_target	=> "link",
		exp_add_error	=> "yes",
		exp_rem_error	=> "yes",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda", NAME="link", SYMLINK+="."
EOF
	},
	{
		desc		=> "symlink node to itself",
		subsys		=> "tty",
		devpath		=> "/devices/virtual/tty/tty0",
		exp_name	=> "link",
		exp_target	=> "link",
		exp_add_error	=> "yes",
		exp_rem_error	=> "yes",
		option		=> "clean",
		rules		=> <<EOF
KERNEL=="tty0", NAME="link", SYMLINK+="link"
EOF
	},
	{
		desc		=> "symlink %n substitution",
		subsys		=> "tty",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "symlink0",
		exp_target	=> "ttyACM0",
		rules		=> <<EOF
KERNEL=="ttyACM[0-9]*", NAME="ttyACM%n", SYMLINK+="symlink%n"
EOF
	},
	{
		desc		=> "symlink %k substitution",
		subsys		=> "tty",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "symlink-ttyACM0",
		exp_target	=> "ttyACM0",
		rules		=> <<EOF
KERNEL=="ttyACM[0-9]*", NAME="ttyACM%n", SYMLINK+="symlink-%k"
EOF
	},
	{
		desc		=> "symlink %M:%m substitution",
		subsys		=> "tty",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "major-166:0",
		exp_target	=> "ttyACM0",
		rules		=> <<EOF
KERNEL=="ttyACM[0-9]*", NAME="ttyACM%n", SYMLINK+="major-%M:%m"
EOF
	},
	{
		desc		=> "symlink %b substitution",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "symlink-0:0:0:0",
		exp_target	=> "node",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda", NAME="node", SYMLINK+="symlink-%b"
EOF
	},
	{
		desc		=> "symlink %c substitution",
		subsys		=> "tty",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "test",
		exp_target	=> "ttyACM0",
		rules		=> <<EOF
KERNEL=="ttyACM[0-9]*", PROGRAM=="/bin/echo test" NAME="ttyACM%n", SYMLINK+="%c"
EOF
	},
	{
		desc		=> "symlink %c{N} substitution",
		subsys		=> "tty",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "test",
		exp_target	=> "ttyACM0",
		rules		=> <<EOF
KERNEL=="ttyACM[0-9]*", PROGRAM=="/bin/echo symlink test this" NAME="ttyACM%n", SYMLINK+="%c{2}"
EOF
	},
	{
		desc		=> "symlink %c{N+} substitution",
		subsys		=> "tty",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "this",
		exp_target	=> "ttyACM0",
		rules		=> <<EOF
KERNEL=="ttyACM[0-9]*", PROGRAM=="/bin/echo symlink test this" NAME="ttyACM%n", SYMLINK+="%c{2+}"
EOF
	},
	{
		desc		=> "symlink only rule with %c{N+}",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "test",
		exp_target	=> "link",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda", PROGRAM=="/bin/echo link test this" SYMLINK+="%c{2+}"
SUBSYSTEMS=="scsi", KERNEL=="sda", NAME="link", SYMLINK+="symlink0"
EOF
	},
	{
		desc		=> "symlink %s{filename} substitution",
		subsys		=> "tty",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "166:0",
		exp_target	=> "ttyACM0",
		rules		=> <<EOF
KERNEL=="ttyACM[0-9]*", NAME="ttyACM%n", SYMLINK+="%s{dev}"
EOF
	},
	{
		desc		=> "symlink %Ns{filename} substitution",
		subsys		=> "tty",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "166",
		exp_target	=> "ttyACM0",
		rules		=> <<EOF
KERNEL=="ttyACM[0-9]*", NAME="ttyACM%n", SYMLINK+="%3s{dev}"
EOF
	},
	{
		desc		=> "program result substitution (numbered part of)",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
		exp_name	=> "link1",
		exp_target	=> "node",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", PROGRAM=="/bin/echo -n node link1 link2", RESULT=="node *", NAME="%c{1}", SYMLINK+="%c{2} %c{3}"
EOF
	},
	{
		desc		=> "program result substitution (numbered part of+)",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda5",
		exp_name	=> "link4",
		exp_target	=> "node",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", PROGRAM=="/bin/echo -n node link1 link2 link3 link4", RESULT=="node *", NAME="%c{1}", SYMLINK+="%c{2+}"
EOF
	},
	{
		desc		=> "ignore rule test",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "nothing",
		not_exp_name	=> "node",
		exp_add_error	=> "yes",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda", NAME="node", OPTIONS="ignore_device"
EOF
	},
	{
		desc		=> "all_partitions, option-only rule",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "node6",
		rules		=> <<EOF
SUBSYSTEM=="block", OPTIONS="all_partitions"
SUBSYSTEMS=="scsi", KERNEL=="sda", NAME="node"
EOF
	},
	{
		desc		=> "all_partitions, option-only rule (fail on partition)",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
		exp_name	=> "node6",
		exp_add_error	=> "yes",
		rules		=> <<EOF
SUBSYSTEM=="block", OPTIONS="all_partitions"
SUBSYSTEMS=="scsi", KERNEL=="sda", NAME="node"
EOF
	},
	{
		desc		=> "ignore remove event test",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "node",
		exp_rem_error	=> "yes",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda", NAME="node", OPTIONS="ignore_remove"
EOF
	},
	{
		desc		=> "ignore remove event test (with all partitions)",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "node14",
		exp_rem_error	=> "yes",
		option		=> "clean",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda", NAME="node", OPTIONS="ignore_remove, all_partitions"
EOF
	},
	{
		desc		=> "SUBSYSTEM match test",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "node",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda", NAME="should_not_match", SUBSYSTEM=="vc"
SUBSYSTEMS=="scsi", KERNEL=="sda", NAME="node", SUBSYSTEM=="block"
SUBSYSTEMS=="scsi", KERNEL=="sda", NAME="should_not_match2", SUBSYSTEM=="vc"
EOF
	},
	{
		desc		=> "DRIVERS match test",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "node",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda", NAME="should_not_match", DRIVERS=="sd-wrong"
SUBSYSTEMS=="scsi", KERNEL=="sda", NAME="node", DRIVERS=="sd"
EOF
	},
	{
		desc		=> "temporary node creation test",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "node",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda", PROGRAM=="/usr/bin/test -b %N" NAME="node"
EOF
	},
	{
		desc		=> "devpath substitution test",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "sda",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda", PROGRAM=="/bin/echo %p", RESULT=="/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda" NAME="%k"
EOF
	},
	{
		desc		=> "parent node name substitution test sequence 1/2 (keep)",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "main_device",
		option		=> "keep",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda", NAME="main_device"
EOF
	},
	{
		desc		=> "parent node name substitution test sequence 2/2 (clean)",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
		exp_name	=> "main_device-part-1",
		option		=> "clean",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda1", NAME="%P-part-1"
EOF
	},
	{
		desc		=> "udev_root substitution",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
		exp_name	=> "start-udev-root-end",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda1", NAME="start-%r-end"
EOF
	},
	{
		desc		=> "last_rule option",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
		exp_name	=> "last",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda1", SYMLINK+="last", OPTIONS="last_rule"
SUBSYSTEMS=="scsi", KERNEL=="sda1", NAME="very-last"
EOF
	},
	{
		desc		=> "negation KERNEL!=",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
		exp_name	=> "match",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNEL!="sda1", NAME="matches-but-is-negated"
SUBSYSTEMS=="scsi", KERNEL=="sda1", NAME="before"
SUBSYSTEMS=="scsi", KERNEL!="xsda1", NAME="match"
EOF
	},
	{
		desc		=> "negation SUBSYSTEM!=",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
		exp_name	=> "not-anything",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", SUBSYSTEM=="block", KERNEL!="sda1", NAME="matches-but-is-negated"
SUBSYSTEMS=="scsi", KERNEL=="sda1", NAME="before"
SUBSYSTEMS=="scsi", SUBSYSTEM!="anything", NAME="not-anything"
EOF
	},
	{
		desc		=> "negation PROGRAM!= exit code",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
		exp_name	=> "nonzero-program",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda1", NAME="before"
KERNEL=="sda1", PROGRAM!="/bin/false", NAME="nonzero-program"
EOF
	},
	{
		desc		=> "test for whitespace between the operator",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
		exp_name	=> "true",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda1", NAME="before"
KERNEL   ==   "sda1"     ,    NAME   =    "true"
EOF
	},
	{
		desc		=> "ENV{} test",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
		exp_name	=> "true",
		rules		=> <<EOF
ENV{ENV_KEY_TEST}="test"
SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ENV_KEY_TEST}=="go", NAME="wrong"
SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ENV_KEY_TEST}=="test", NAME="true"
SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ENV_KEY_TEST}=="bad", NAME="bad"
EOF
	},
	{
		desc		=> "ENV{} test",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
		exp_name	=> "true",
		rules		=> <<EOF
ENV{ENV_KEY_TEST}="test"
SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ENV_KEY_TEST}=="go", NAME="wrong"
SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ENV_KEY_TEST}=="yes", ENV{ACTION}=="add", ENV{DEVPATH}=="*/block/sda/sdax1", NAME="no"
SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ENV_KEY_TEST}=="test", ENV{ACTION}=="add", ENV{DEVPATH}=="*/block/sda/sda1", NAME="true"
SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ENV_KEY_TEST}=="bad", NAME="bad"
EOF
	},
	{
		desc		=> "ENV{} test (assign)",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
		exp_name	=> "true",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ASSIGN}="true"
SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ASSIGN}=="yes", NAME="no"
SUBSYSTEMS=="scsi", KERNEL=="sda1", NAME="before"
SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ASSIGN}=="true", NAME="true"
EOF
	},
	{
		desc		=> "ENV{} test (assign 2 times)",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
		exp_name	=> "true",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ASSIGN}="true"
SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ASSIGN}="absolutely-\$env{ASSIGN}"
SUBSYSTEMS=="scsi", KERNEL=="sda1", NAME="before"
SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ASSIGN}=="yes", NAME="no"
SUBSYSTEMS=="scsi", KERNEL=="sda1", ENV{ASSIGN}=="absolutely-true", NAME="true"
EOF
	},
	{
		desc		=> "ENV{} test (assign2)",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
		exp_name	=> "part",
		rules		=> <<EOF
SUBSYSTEM=="block", KERNEL=="*[0-9]", ENV{PARTITION}="true", ENV{MAINDEVICE}="false"
SUBSYSTEM=="block", KERNEL=="*[!0-9]", ENV{PARTITION}="false", ENV{MAINDEVICE}="true"
ENV{MAINDEVICE}=="true", NAME="disk"
SUBSYSTEM=="block", NAME="before"
ENV{PARTITION}=="true", NAME="part"
EOF
	},
	{
		desc		=> "untrusted string sanitize",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
		exp_name	=> "sane",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda1", PROGRAM=="/bin/echo -e name; (/sbin/badprogram)", RESULT=="name_ _/sbin/badprogram_", NAME="sane"
EOF
	},
	{
		desc		=> "untrusted string sanitize (don't replace utf8)",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
		exp_name	=> "uber",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda1", PROGRAM=="/bin/echo -e \\xc3\\xbcber" RESULT=="\xc3\xbcber", NAME="uber"
EOF
	},
	{
		desc		=> "untrusted string sanitize (replace invalid utf8)",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
		exp_name	=> "replaced",
		rules		=> <<EOF
SUBSYSTEMS=="scsi", KERNEL=="sda1", PROGRAM=="/bin/echo -e \\xef\\xe8garbage", RESULT=="__garbage", NAME="replaced"
EOF
	},
	{
		desc		=> "read sysfs value from parent device",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "serial-354172020305000",
		rules		=> <<EOF
KERNEL=="ttyACM*", ATTRS{serial}=="?*", NAME="serial-%s{serial}"
EOF
	},
	{
		desc		=> "match against empty key string",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "ok",
		rules		=> <<EOF
KERNEL=="sda", ATTRS{nothing}!="", NAME="not-1-ok"
KERNEL=="sda", ATTRS{nothing}=="", NAME="not-2-ok"
KERNEL=="sda", ATTRS{vendor}!="", NAME="ok"
KERNEL=="sda", ATTRS{vendor}=="", NAME="not-3-ok"
EOF
	},
	{
		desc		=> "check ACTION value",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "ok",
		rules		=> <<EOF
ACTION=="unknown", KERNEL=="sda", NAME="unknown-not-ok"
ACTION=="add", KERNEL=="sda", NAME="ok"
EOF
	},
	{
		desc		=> "apply NAME final",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "link",
		exp_target	=> "ok",
		rules		=> <<EOF
KERNEL=="sda", NAME:="ok"
KERNEL=="sda", NAME="not-ok"
KERNEL=="sda", SYMLINK+="link"
EOF
	},
	{
		desc		=> "test RUN key",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "testsymlink",
		exp_target	=> "ok",
		exp_rem_error	=> "yes",
		option		=> "clean",
		rules		=> <<EOF
KERNEL=="sda", NAME="ok", RUN+="/bin/ln -s ok %r/testsymlink"
KERNEL=="sda", NAME="not-ok"
EOF
	},
	{
		desc		=> "test RUN key and DEVNAME",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "testsymlink",
		exp_target	=> "ok",
		exp_rem_error	=> "yes",
		option		=> "clean",
		rules		=> <<EOF
KERNEL=="sda", NAME="not-ok"
KERNEL=="sda", NAME="ok", RUN+="/bin/sh -c 'ln -s `basename \$\$DEVNAME` %r/testsymlink'"
EOF
	},
	{
		desc		=> "test RUN key remove",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "testsymlink2",
		exp_target	=> "ok2",
		rules		=> <<EOF
KERNEL=="sda", NAME="ok2", RUN+="/bin/ln -s ok2 %r/testsymlink2"
KERNEL=="sda", ACTION=="remove", RUN+="/bin/rm -f %r/testsymlink2"
KERNEL=="sda", NAME="not-ok2"
EOF
	},
	{
		desc		=> "final assignment",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "ok",
		exp_perms	=> "root:tty:0640",
		rules		=> <<EOF
KERNEL=="sda", GROUP:="tty"
KERNEL=="sda", GROUP="not-ok", MODE="0640", NAME="ok"
EOF
	},
	{
		desc		=> "final assignment 2",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "ok",
		exp_perms	=> "root:tty:0640",
		rules		=> <<EOF
KERNEL=="sda", GROUP:="tty"
SUBSYSTEM=="block", MODE:="640"
KERNEL=="sda", GROUP="not-ok", MODE="0666", NAME="ok"
EOF
	},
	{
		desc		=> "env substitution",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "node-add-me",
		rules		=> <<EOF
KERNEL=="sda", MODE="0666", NAME="node-\$env{ACTION}-me"
EOF
	},
	{
		desc		=> "reset list to current value",
		subsys		=> "tty",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "three",
		not_exp_name	=> "two",
		exp_target	=> "node",
		rules		=> <<EOF
KERNEL=="ttyACM[0-9]*", SYMLINK+="one"
KERNEL=="ttyACM[0-9]*", SYMLINK+="two"
KERNEL=="ttyACM[0-9]*", SYMLINK="three"
KERNEL=="ttyACM[0-9]*", NAME="node"
EOF
	},
	{
		desc		=> "test empty NAME",
		subsys		=> "tty",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "<none>",
		not_exp_name	=> "ttyACM0",
		exp_add_error	=> "yes",
		rules		=> <<EOF
KERNEL=="ttyACM[0-9]*", NAME=""
EOF
	},
	{
		desc		=> "test empty NAME (empty override)",
		subsys		=> "tty",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "<none>",
		not_exp_name	=> "wrong",
		exp_add_error	=> "yes",
		rules		=> <<EOF
KERNEL=="ttyACM[0-9]*", NAME="wrong"
KERNEL=="ttyACM[0-9]*", NAME=""
EOF
	},
	{
		desc		=> "test empty NAME (non-empty override)",
		subsys		=> "tty",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "right",
		rules		=> <<EOF
KERNEL=="ttyACM[0-9]*", NAME=""
KERNEL=="ttyACM[0-9]*", NAME="wrong"
KERNEL=="ttyACM[0-9]*", NAME="right"
EOF
	},
	{
		desc		=> "test multi matches",
		subsys		=> "tty",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "right",
		rules		=> <<EOF
KERNEL=="ttyACM*", NAME="before"
KERNEL=="ttyACM*|nothing", NAME="right"
EOF
	},
	{
		desc		=> "test multi matches 2",
		subsys		=> "tty",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "right",
		rules		=> <<EOF
KERNEL=="dontknow*|*nothing", NAME="nomatch"
KERNEL=="ttyACM*", NAME="before"
KERNEL=="dontknow*|ttyACM*|nothing*", NAME="right"
EOF
	},
	{
		desc		=> "test multi matches 3",
		subsys		=> "tty",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "right",
		rules		=> <<EOF
KERNEL=="dontknow|nothing", NAME="nomatch"
KERNEL=="dontknow|ttyACM0a|nothing|attyACM0", NAME="wrong1"
KERNEL=="X|attyACM0|dontknow|ttyACM0a|nothing|attyACM0", NAME="wrong2"
KERNEL=="dontknow|ttyACM0|nothing", NAME="right"
EOF
	},
	{
		desc		=> "test multi matches 4",
		subsys		=> "tty",
		devpath		=> "/devices/pci0000:00/0000:00:1d.7/usb5/5-2/5-2:1.0/tty/ttyACM0",
		exp_name	=> "right",
		rules		=> <<EOF
KERNEL=="dontknow|nothing", NAME="nomatch"
KERNEL=="dontknow|ttyACM0a|nothing|attyACM0", NAME="wrong1"
KERNEL=="X|attyACM0|dontknow|ttyACM0a|nothing|attyACM0", NAME="wrong2"
KERNEL=="all|dontknow|ttyACM0", NAME="right"
KERNEL=="ttyACM0a|nothing", NAME="wrong3"
EOF
	},
	{
		desc		=> "IMPORT parent test sequence 1/2 (keep)",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "parent",
		option		=> "keep",
		rules		=> <<EOF
KERNEL=="sda", IMPORT="/bin/echo -e \'PARENT_KEY=parent_right\\nWRONG_PARENT_KEY=parent_wrong'"
KERNEL=="sda", NAME="parent"
EOF
	},
	{
		desc		=> "IMPORT parent test sequence 2/2 (keep)",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
		exp_name	=> "parentenv-parent_right",
		option		=> "clean",
		rules		=> <<EOF
KERNEL=="sda1", IMPORT{parent}="PARENT*", NAME="parentenv-\$env{PARENT_KEY}\$env{WRONG_PARENT_KEY}"
EOF
	},
	{
		desc		=> "GOTO test",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
		exp_name	=> "right",
		rules		=> <<EOF
KERNEL=="sda1", GOTO="TEST"
KERNEL=="sda1", NAME="wrong"
KERNEL=="sda1", GOTO="BAD"
KERNEL=="sda1", NAME="", LABEL="NO"
KERNEL=="sda1", NAME="right", LABEL="TEST"
KERNEL=="sda1", LABEL="BAD"
EOF
	},
	{
		desc		=> "NAME compare test",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
		exp_name	=> "link",
		exp_target	=> "node",
		not_exp_name	=> "wronglink",
		rules		=> <<EOF
KERNEL=="sda1", NAME="node"
KERNEL=="sda2", NAME="wrong"
KERNEL=="sda1", NAME=="wrong*", SYMLINK+="wronglink"
KERNEL=="sda1", NAME=="?*", SYMLINK+="link"
KERNEL=="sda1", NAME=="node*", SYMLINK+="link2"
EOF
	},
	{
		desc		=> "NAME compare test 2",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
		exp_name	=> "link2",
		exp_target	=> "sda1",
		not_exp_name	=> "link",
		rules		=> <<EOF
KERNEL=="sda1", NAME=="?*", SYMLINK+="link"
KERNEL=="sda1", NAME!="?*", SYMLINK+="link2"
EOF
	},
	{
		desc		=> "invalid key operation",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
		exp_name	=> "yes",
		rules		=> <<EOF
KERNEL="sda1", NAME="no"
KERNEL=="sda1", NAME="yes"
EOF
	},
	{
		desc		=> "operator chars in attribute",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "yes",
		rules		=> <<EOF
KERNEL=="sda", ATTR{test:colon+plus}=="?*", NAME="yes"
EOF
	},
	{
		desc		=> "overlong comment line",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1",
		exp_name	=> "yes",
		rules		=> <<EOF
# 012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789
   # 012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789
KERNEL=="sda1", NAME=="no"
KERNEL=="sda1", NAME="yes"
EOF
	},
	{
		desc		=> "magic subsys/kernel lookup",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "00:16:41:e2:8d:ff",
		rules		=> <<EOF
KERNEL=="sda", NAME="\$attr{[net/eth0]address}"
EOF
	},
	{
		desc		=> "TEST absolute path",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "there",
		rules		=> <<EOF
TEST=="/etc/hosts", NAME="there"
TEST!="/etc/hosts", NAME="notthere"
EOF
	},
	{
		desc		=> "TEST subsys/kernel lookup",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "yes",
		rules		=> <<EOF
KERNEL=="sda", TEST=="[net/eth0]", NAME="yes"
EOF
	},
	{
		desc		=> "TEST relative path",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "relative",
		rules		=> <<EOF
KERNEL=="sda", TEST=="size", NAME="relative"
EOF
	},
	{
		desc		=> "TEST wildcard substitution (find queue/nr_requests)",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "found-subdir",
		rules		=> <<EOF
KERNEL=="sda", TEST=="*/nr_requests", NAME="found-subdir"
EOF
	},
	{
		desc		=> "TEST MODE=0000",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "sda",
		exp_perms	=> "0:0:0000",
		rules		=> <<EOF
KERNEL=="sda", MODE="0000"
EOF
	},
	{
		desc		=> "TEST PROGRAM feeds MODE",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "sda",
		exp_perms	=> "0:0:0400",
		rules		=> <<EOF
KERNEL=="sda", MODE="666"
KERNEL=="sda", PROGRAM=="/bin/echo 0 0 0400", OWNER="%c{1}", GROUP="%c{2}", MODE="%c{3}"
EOF
	},
	{
		desc		=> "TEST PROGRAM feeds MODE with overflow",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "sda",
		exp_perms	=> "0:0:0660",
		rules		=> <<EOF
KERNEL=="sda", MODE="440"
KERNEL=="sda", PROGRAM=="/bin/echo 0 0 0400letsdoabuffferoverflow0123456789012345789012345678901234567890", OWNER="%c{1}", GROUP="%c{2}", MODE="%c{3}"
EOF
	},
	{
		desc		=> "magic [subsys/sysname] attribute substitution",
		subsys		=> "block",
		devpath		=> "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
		exp_name	=> "sda-8741C4G-end",
		exp_perms	=> "0:0:0660",
		rules		=> <<EOF
KERNEL=="sda", PROGRAM="/bin/true create-envp"
KERNEL=="sda", ENV{TESTENV}="change-envp"
KERNEL=="sda", NAME="%k-%s{[dmi/id]product_name}-end", RUN+="socket:@/org/kernel/udev/monitor"
EOF
	},
);

# set env
$ENV{SYSFS_PATH} = $sysfs;
$ENV{UDEV_CONFIG_FILE} = $udev_conf;

sub udev {
	my ($action, $subsys, $devpath, $rules) = @_;

	$ENV{DEVPATH} = $devpath;

	# create temporary rules
	open CONF, ">$udev_rules" || die "unable to create rules file: $udev_rules";
	print CONF $$rules;
	close CONF;

	$ENV{ACTION} = $action;
	$ENV{SUBSYSTEM} = $subsys;
	if ($valgrind > 0) {
		system("$udev_bin_valgrind");
	} else {
		system("$udev_bin");
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
	}
}

sub symlink_test {
	my ($rules) = @_;

	my $output = `ls -l $PWD/$udev_root$rules->{exp_name}`;

	if ($output =~ m/(.*)-> (.*)/) {
		if ($2 eq $rules->{exp_target}) {
			print "symlink:     ok\n";
		} else {
			print "  expected symlink from: \'$rules->{exp_name}\' to \'$rules->{exp_target}\'\n";
			print "  created symlink from: \'$rules->{exp_name}\' to \'$2\'\n";
			print "symlink: error";
			if ($rules->{exp_add_error}) {
				print " as expected\n";
			} else {
				print "\n";
				$error++;
			}
		}
	} else {
		print "  expected symlink from: \'$rules->{exp_name}\' to \'$rules->{exp_target}\'\n";
		print "symlink:     not created";
		if ($rules->{exp_add_error}) {
			print " as expected\n";
		} else {
			print "\n";
			$error++;
		}
	}
}

sub make_udev_root {
	system("rm -rf $udev_root");
	mkdir($udev_root) || die "unable to create udev_root: $udev_root\n";
	# setting group and mode of udev_root ensures the tests work
	# even if the parent directory has setgid bit enabled.
	chown (0, 0, $udev_root) || die "unable to chown $udev_root\n";
	chmod (0755, $udev_root) || die "unable to chmod $udev_root\n";
}

sub run_test {
	my ($rules, $number) = @_;

	print "TEST $number: $rules->{desc}\n";

	if ($rules->{exp_target}) {
		print "device \'$rules->{devpath}\' expecting symlink '$rules->{exp_name}' to node \'$rules->{exp_target}\'\n";
	} else {
		print "device \'$rules->{devpath}\' expecting node \'$rules->{exp_name}\'\n";
	}


	udev("add", $rules->{subsys}, $rules->{devpath}, \$rules->{rules});
	if (defined($rules->{not_exp_name})) {
		if ((-e "$PWD/$udev_root$rules->{not_exp_name}") ||
		    (-l "$PWD/$udev_root$rules->{not_exp_name}")) {
			print "nonexistent: error \'$rules->{not_exp_name}\' not expected to be there\n";
			$error++
		}
	}

	if ((-e "$PWD/$udev_root$rules->{exp_name}") ||
	    (-l "$PWD/$udev_root$rules->{exp_name}")) {

		my ($dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size,
		    $atime, $mtime, $ctime, $blksize, $blocks) = stat("$PWD/$udev_root$rules->{exp_name}");

		if (defined($rules->{exp_perms})) {
			permissions_test($rules, $uid, $gid, $mode);
		}
		if (defined($rules->{exp_majorminor})) {
			major_minor_test($rules, $rdev);
		}
		if (defined($rules->{exp_target})) {
			symlink_test($rules);
		}
		print "add:         ok\n";
	} else {
		print "add:         error";
		if ($rules->{exp_add_error}) {
			print " as expected\n";
		} else {
			print "\n";
			system("tree $udev_root");
			print "\n";
			$error++;
		}
	}

	if (defined($rules->{option}) && $rules->{option} eq "keep") {
		print "\n\n";
		return;
	}

	udev("remove", $rules->{subsys}, $rules->{devpath}, \$rules->{rules});
	if ((-e "$PWD/$udev_root$rules->{exp_name}") ||
	    (-l "$PWD/$udev_root$rules->{exp_name}")) {
		print "remove:      error";
		if ($rules->{exp_rem_error}) {
			print " as expected\n";
		} else {
			print "\n";
			system("tree $udev_root");
			print "\n";
			$error++;
		}
	} else {
		print "remove:      ok\n";
	}

	print "\n";

	if (defined($rules->{option}) && $rules->{option} eq "clean") {
		make_udev_root ();
	}

}

# only run if we have root permissions
# due to mknod restrictions
if (!($<==0)) {
	print "Must have root permissions to run properly.\n";
	exit;
}

# prepare
make_udev_root();

# create config file
open CONF, ">$udev_conf" || die "unable to create config file: $udev_conf";
print CONF "udev_root=\"$udev_root\"\n";
print CONF "udev_rules=\"$PWD\"\n";
print CONF "udev_log=\"err\"\n";
close CONF;

my $test_num = 1;
my @list;

foreach my $arg (@ARGV) {
	if ($arg =~ m/--valgrind/) {
		$valgrind = 1;
		printf("using valgrind\n");
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

print "$error errors occured\n\n";

# cleanup
system("rm -rf $udev_root");
unlink($udev_rules);
unlink($udev_conf);

if ($error > 0) {
    exit(1);
}
exit(0);
