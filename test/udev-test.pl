#!/usr/bin/perl

# udev-test
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
# Kay Sievers <kay.sievers@vrfy.org>, 2003
# Leann Ogasawara <ogasawara@osdl.org>, 2004

use warnings;
use strict;

my $PWD		= $ENV{PWD};
my $sysfs	= "sys/";
my $udev_bin	= "../udev";
my $udev_root	= "udev-root/"; # !!! directory will be removed !!!
my $udev_db	= ".udevdb";
my $udev_conf	= "udev-test.conf";
my $udev_rules	= "udev-test.rules";

# uncomment following line to run udev with valgrind.
# Should make this a runtime option to the script someday...
#my $udev_bin  = "valgrind --tool=memcheck --leak-check=yes   ../udev";

my @tests = (
	{
		desc		=> "label test of scsi disc",
		subsys		=> "block",
		devpath		=> "/block/sda",
		exp_name	=> "boot_disk" ,
		rules		=> <<EOF
BUS=="scsi", SYSFS{vendor}=="IBM-ESXS", NAME="boot_disk%n"
KERNEL=="ttyUSB0", NAME="visor"
EOF
	},
	{
		desc		=> "label test of scsi partition",
		subsys		=> "block",
		devpath		=> "/block/sda/sda1",
		exp_name	=> "boot_disk1" ,
		rules		=> <<EOF
BUS=="scsi", SYSFS{vendor}=="IBM-ESXS", NAME="boot_disk%n"
EOF
	},
	{
		desc		=> "label test of pattern match",
		subsys		=> "block",
		devpath		=> "/block/sda/sda1",
		exp_name	=> "boot_disk1" ,
		rules		=> <<EOF
BUS=="scsi", SYSFS{vendor}=="?IBM-ESXS", NAME="boot_disk%n-1"
BUS=="scsi", SYSFS{vendor}=="IBM-ESXS?", NAME="boot_disk%n-2"
BUS=="scsi", SYSFS{vendor}=="IBM-ES??", NAME="boot_disk%n"
BUS=="scsi", SYSFS{vendor}=="IBM-ESXSS", NAME="boot_disk%n-3"
EOF
	},
	{
		desc		=> "label test of multiple sysfs files",
		subsys		=> "block",
		devpath		=> "/block/sda/sda1",
		exp_name	=> "boot_disk1" ,
		rules		=> <<EOF
BUS=="scsi", SYSFS{vendor}=="IBM-ESXS", SYSFS{model}=="ST336605LW   !#", NAME="boot_diskX%n"
BUS=="scsi", SYSFS{vendor}=="IBM-ESXS", SYSFS{model}=="ST336605LW    !#", NAME="boot_disk%n"
EOF
	},
	{
		desc		=> "label test of max sysfs files",
		subsys		=> "block",
		devpath		=> "/block/sda/sda1",
		exp_name	=> "boot_disk1" ,
		rules		=> <<EOF
BUS=="scsi", SYSFS{vendor}=="IBM-ESXS", SYSFS{model}=="ST336605LW    !#", SYSFS{scsi_level}=="4", SYSFS{rev}=="B245", SYSFS{type}=="2", SYSFS{queue_depth}=="32", NAME="boot_diskXX%n"
BUS=="scsi", SYSFS{vendor}=="IBM-ESXS", SYSFS{model}=="ST336605LW    !#", SYSFS{scsi_level}=="4", SYSFS{rev}=="B245", SYSFS{type}=="0", NAME="boot_disk%n"
EOF
	},
	{
		desc		=> "catch device by *",
		subsys		=> "tty",
		devpath		=> "/class/tty/ttyUSB0",
		exp_name	=> "visor/0" ,
		rules		=> <<EOF
KERNEL=="ttyUSB*", NAME="visor/%n"
EOF
	},
	{
		desc		=> "catch device by * - take 2",
		subsys		=> "tty",
		devpath		=> "/class/tty/ttyUSB0",
		exp_name	=> "visor/0" ,
		rules		=> <<EOF
KERNEL=="*USB1", NAME="bad"
KERNEL=="*USB0", NAME="visor/%n"
EOF
	},
	{
		desc		=> "catch device by ?",
		subsys		=> "tty",
		devpath		=> "/class/tty/ttyUSB0",
		exp_name	=> "visor/0" ,
		rules		=> <<EOF
KERNEL=="ttyUSB??*", NAME="visor/%n-1"
KERNEL=="ttyUSB??", NAME="visor/%n-2"
KERNEL=="ttyUSB?", NAME="visor/%n"
EOF
	},
	{
		desc		=> "catch device by character class",
		subsys		=> "tty",
		devpath		=> "/class/tty/ttyUSB0",
		exp_name	=> "visor/0" ,
		rules		=> <<EOF
KERNEL=="ttyUSB[A-Z]*", NAME="visor/%n-1"
KERNEL=="ttyUSB?[0-9]", NAME="visor/%n-2"
KERNEL=="ttyUSB[0-9]*", NAME="visor/%n"
EOF
	},
	{
		desc		=> "replace kernel name",
		subsys		=> "tty",
		devpath		=> "/class/tty/ttyUSB0",
		exp_name	=> "visor" ,
		rules		=> <<EOF
KERNEL=="ttyUSB0", NAME="visor"
EOF
	},
	{
		desc		=> "Handle comment lines in config file (and replace kernel name)",
		subsys		=> "tty",
		devpath		=> "/class/tty/ttyUSB0",
		exp_name	=> "visor" ,
		rules		=> <<EOF
# this is a comment
KERNEL=="ttyUSB0", NAME="visor"

EOF
	},
	{
		desc		=> "Handle comment lines in config file with whitespace (and replace kernel name)",
		subsys		=> "tty",
		devpath		=> "/class/tty/ttyUSB0",
		exp_name	=> "visor" ,
		rules		=> <<EOF
 # this is a comment with whitespace before the comment 
KERNEL=="ttyUSB0", NAME="visor"

EOF
	},
	{
		desc		=> "Handle whitespace only lines (and replace kernel name)",
		subsys		=> "tty",
		devpath		=> "/class/tty/ttyUSB0",
		exp_name	=> "whitespace" ,
		rules		=> <<EOF

 

 # this is a comment with whitespace before the comment 
KERNEL=="ttyUSB0", NAME="whitespace"

 

EOF
	},
	{
		desc		=> "Handle empty lines in config file (and replace kernel name)",
		subsys		=> "tty",
		devpath		=> "/class/tty/ttyUSB0",
		exp_name	=> "visor" ,
		rules		=> <<EOF

KERNEL=="ttyUSB0", NAME="visor"

EOF
	},
	{
		desc		=> "Handle backslashed multi lines in config file (and replace kernel name)",
		subsys		=> "tty",
		devpath		=> "/class/tty/ttyUSB0",
		exp_name	=> "visor" ,
		rules		=> <<EOF
KERNEL=="ttyUSB0", \\
NAME="visor"

EOF
	},
	{
		desc		=> "preserve backslashes, if they are not for a newline",
		subsys		=> "tty",
		devpath		=> "/class/tty/ttyUSB0",
		exp_name	=> "aaa",
		rules		=> <<EOF
KERNEL=="ttyUSB0", PROGRAM=="/bin/echo -e \\101", RESULT=="A", NAME="aaa"
EOF
	},
	{
		desc		=> "Handle stupid backslashed multi lines in config file (and replace kernel name)",
		subsys		=> "tty",
		devpath		=> "/class/tty/ttyUSB0",
		exp_name	=> "visor" ,
		rules		=> <<EOF

#
\\

\\\\

#\\

KERNEL=="ttyUSB0", \\
	NAME="visor"

EOF
	},
	{
		desc		=> "subdirectory handling",
		subsys		=> "tty",
		devpath		=> "/class/tty/ttyUSB0",
		exp_name	=> "sub/direct/ory/visor" ,
		rules		=> <<EOF
KERNEL=="ttyUSB0", NAME="sub/direct/ory/visor"
EOF
	},
	{
		desc		=> "place on bus of scsi partition",
		subsys		=> "block",
		devpath		=> "/block/sda/sda3",
		exp_name	=> "first_disk3" ,
		rules		=> <<EOF
BUS=="scsi", ID=="0:0:0:0", NAME="first_disk%n"
EOF
	},
	{
		desc		=> "test substitution chars",
		subsys		=> "block",
		devpath		=> "/block/sda/sda3",
		exp_name	=> "Major:8:minor:3:kernelnumber:3:bus:0:0:0:0" ,
		rules		=> <<EOF
BUS=="scsi", ID=="0:0:0:0", NAME="Major:%M:minor:%m:kernelnumber:%n:bus:%b"
EOF
	},
	{
		desc		=> "test substitution chars (with length limit)",
		subsys		=> "block",
		devpath		=> "/block/sda/sda3",
		exp_name	=> "M8-m3-n3-b0:0-sIBM" ,
		rules		=> <<EOF
BUS=="scsi", ID=="0:0:0:0", NAME="M%M-m%m-n%n-b%3b-s%3s{vendor}"
EOF
	},
	{
		desc		=> "import of shell-value file",
		subsys		=> "block",
		devpath		=> "/block/sda",
		exp_name	=> "subdir/sys/node" ,
		rules		=> <<EOF
BUS=="scsi", IMPORT="test.all", NAME="subdir%E{SYSFSDIR}/node"
KERNEL=="ttyUSB0", NAME="visor"
EOF
	},
	{
		desc		=> "import of shell-value returned from program",
		subsys		=> "block",
		devpath		=> "/block/sda",
		exp_name	=> "node12345678",
		rules		=> <<EOF
BUS=="scsi", IMPORT{exec}="/bin/echo -e \' TEST_KEY=12345678  \\n  TEST_key2=98765 \'", NAME="node\$env{TEST_KEY}"
KERNEL=="ttyUSB0", NAME="visor"
EOF
	},
	{
		desc		=> "sustitution of sysfs value (%s{file})",
		subsys		=> "block",
		devpath		=> "/block/sda",
		exp_name	=> "disk-IBM-ESXS-sda" ,
		rules		=> <<EOF
BUS=="scsi", SYSFS{vendor}=="IBM-ESXS", NAME="disk-%s{vendor}-%k"
KERNEL=="ttyUSB0", NAME="visor"
EOF
	},
	{
		desc		=> "program result substitution",
		subsys		=> "block",
		devpath		=> "/block/sda/sda3",
		exp_name	=> "special-device-3" ,
		rules		=> <<EOF
BUS=="scsi", PROGRAM=="/bin/echo -n special-device", RESULT=="-special-*", NAME="%c-1-%n"
BUS=="scsi", PROGRAM=="/bin/echo -n special-device", RESULT=="special--*", NAME="%c-2-%n"
BUS=="scsi", PROGRAM=="/bin/echo -n special-device", RESULT=="special-device-", NAME="%c-3-%n"
BUS=="scsi", PROGRAM=="/bin/echo -n special-device", RESULT=="special-devic", NAME="%c-4-%n"
BUS=="scsi", PROGRAM=="/bin/echo -n special-device", RESULT=="special-*", NAME="%c-%n"
EOF
	},
	{
		desc		=> "program result substitution (no argument should be subsystem)",
		subsys		=> "block",
		devpath		=> "/block/sda/sda3",
		exp_name	=> "subsys_block" ,
		rules		=> <<EOF
BUS=="scsi", PROGRAM=="/bin/echo", RESULT=="block", NAME="subsys_block"
EOF
	},
	{
		desc		=> "program result substitution (newline removal)",
		subsys		=> "block",
		devpath		=> "/block/sda/sda3",
		exp_name	=> "newline_removed" ,
		rules		=> <<EOF
BUS=="scsi", PROGRAM=="/bin/echo test", RESULT=="test", NAME="newline_removed"
EOF
	},
	{
		desc		=> "program result substitution",
		subsys		=> "block",
		devpath		=> "/block/sda/sda3",
		exp_name	=> "test-0:0:0:0" ,
		rules		=> <<EOF
BUS=="scsi", PROGRAM=="/bin/echo -n test-%b", RESULT=="test-0:0*", NAME="%c"
EOF
	},
	{
		desc		=> "program with escaped format char (tricky: callout returns format char!)",
		subsys		=> "block",
		devpath		=> "/block/sda/sda3",
		exp_name	=> "escape-3" ,
		rules		=> <<EOF
BUS=="scsi", PROGRAM=="/bin/echo -n escape-%%n", KERNEL=="sda3", NAME="%c"
EOF
	},
	{
		desc		=> "program with lots of arguments",
		subsys		=> "block",
		devpath		=> "/block/sda/sda3",
		exp_name	=> "foo9" ,
		rules		=> <<EOF
BUS=="scsi", PROGRAM=="/bin/echo -n foo3 foo4 foo5 foo6 foo7 foo8 foo9", KERNEL=="sda3", NAME="%c{7}"
EOF
	},
	{
		desc		=> "program with subshell",
		subsys		=> "block",
		devpath		=> "/block/sda/sda3",
		exp_name	=> "bar9" ,
		rules		=> <<EOF
BUS=="scsi", PROGRAM=="/bin/sh -c 'echo foo3 foo4 foo5 foo6 foo7 foo8 foo9 | sed  s/foo9/bar9/'", KERNEL=="sda3", NAME="%c{7}"
EOF
	},
	{
		desc		=> "program arguments combined with apostrophes",
		subsys		=> "block",
		devpath		=> "/block/sda/sda3",
		exp_name	=> "foo7" ,
		rules		=> <<EOF
BUS=="scsi", PROGRAM=="/bin/echo -n 'foo3 foo4'   'foo5   foo6   foo7 foo8'", KERNEL=="sda3", NAME="%c{5}"
EOF
	},
	{
		desc		=> "characters before the %c{N} substitution",
		subsys		=> "block",
		devpath		=> "/block/sda/sda3",
		exp_name	=> "my-foo9" ,
		rules		=> <<EOF
BUS=="scsi", PROGRAM=="/bin/echo -n foo3 foo4 foo5 foo6 foo7 foo8 foo9", KERNEL=="sda3", NAME="my-%c{7}"
EOF
	},
	{
		desc		=> "substitute the second to last argument",
		subsys		=> "block",
		devpath		=> "/block/sda/sda3",
		exp_name	=> "my-foo8" ,
		rules		=> <<EOF
BUS=="scsi", PROGRAM=="/bin/echo -n foo3 foo4 foo5 foo6 foo7 foo8 foo9", KERNEL=="sda3", NAME="my-%c{6}"
EOF
	},
	{
		desc		=> "test substitution by variable name",
		subsys		=> "block",
		devpath		=> "/block/sda/sda3",
		exp_name	=> "Major:8-minor:3-kernelnumber:3-bus:0:0:0:0" ,
		rules		=> <<EOF
BUS=="scsi", ID=="0:0:0:0", NAME="Major:\$major-minor:\$minor-kernelnumber:\$number-bus:\$id"
EOF
	},
	{
		desc		=> "test substitution by variable name 2",
		subsys		=> "block",
		devpath		=> "/block/sda/sda3",
		exp_name	=> "Major:8-minor:3-kernelnumber:3-bus:0:0:0:0" ,
		rules		=> <<EOF
BUS=="scsi", ID=="0:0:0:0", DEVPATH="*/sda/*", NAME="Major:\$major-minor:%m-kernelnumber:\$number-bus:%b"
EOF
	},
	{
		desc		=> "test substitution by variable name 3",
		subsys		=> "block",
		devpath		=> "/block/sda/sda3",
		exp_name	=> "830:0:0:03" ,
		rules		=> <<EOF
BUS=="scsi", ID=="0:0:0:0", DEVPATH="*/sda/*", NAME="%M%m%b%n"
EOF
	},
	{
		desc		=> "test substitution by variable name 4",
		subsys		=> "block",
		devpath		=> "/block/sda/sda3",
		exp_name	=> "833" ,
		rules		=> <<EOF
BUS=="scsi", ID=="0:0:0:0", DEVPATH="*/sda/*", NAME="\$major\$minor\$number"
EOF
	},
	{
		desc		=> "test substitution by variable name 5",
		subsys		=> "block",
		devpath		=> "/block/sda/sda3",
		exp_name	=> "8330:0:0:0" ,
		rules		=> <<EOF
BUS=="scsi", ID=="0:0:0:0", DEVPATH="*/sda/*", NAME="\$major%m%n\$id"
EOF
	},
	{
		desc		=> "invalid program for device with no bus",
		subsys		=> "tty",
		devpath		=> "/class/tty/console",
		exp_name	=> "TTY" ,
		rules		=> <<EOF
BUS=="scsi", PROGRAM=="/bin/echo -n foo", RESULT=="foo", NAME="foo"
KERNEL=="console", NAME="TTY"
EOF
	},
	{
		desc		=> "valid program for device with no bus",
		subsys		=> "tty",
		devpath		=> "/class/tty/console",
		exp_name	=> "foo" ,
		rules		=> <<EOF
PROGRAM=="/bin/echo -n foo", RESULT=="foo", NAME="foo"
KERNEL=="console", NAME="TTY"
EOF
	},
	{
		desc		=> "invalid label for device with no bus",
		subsys		=> "tty",
		devpath		=> "/class/tty/console",
		exp_name	=> "TTY" ,
		rules		=> <<EOF
BUS=="foo", SYSFS{dev}=="5:1", NAME="foo"
KERNEL=="console", NAME="TTY"
EOF
	},
	{
		desc		=> "valid label for device with no bus",
		subsys		=> "tty",
		devpath		=> "/class/tty/console",
		exp_name	=> "foo" ,
		rules		=> <<EOF
SYSFS{dev}=="5:1", NAME="foo"
KERNEL=="console", NAME="TTY"
EOF
	},
	{
		desc		=> "program and bus type match",
		subsys		=> "block",
		devpath		=> "/block/sda",
		exp_name	=> "scsi-0:0:0:0" ,
		rules		=> <<EOF
BUS=="usb", PROGRAM=="/bin/echo -n usb-%b", NAME="%c"
BUS=="scsi", PROGRAM=="/bin/echo -n scsi-%b", NAME="%c"
BUS=="foo", PROGRAM=="/bin/echo -n foo-%b", NAME="%c"
EOF
	},
	{
		desc		=> "create all possible partitions",
		subsys		=> "block",
		devpath		=> "/block/sda",
		exp_name	=> "boot_disk15" ,
		exp_majorminor	=> "8:15",
		rules		=> <<EOF
BUS=="scsi", SYSFS{vendor}=="IBM-ESXS", NAME{all_partitions}="boot_disk"
EOF
	},
	{
		desc		=> "sysfs parent hierarchy",
		subsys		=> "tty",
		devpath		=> "/class/tty/ttyUSB0",
		exp_name	=> "visor" ,
		rules		=> <<EOF
SYSFS{idProduct}=="2008", NAME="visor"
EOF
	},
	{
		desc		=> "name test with ! in the name",
		subsys		=> "block",
		devpath		=> "/block/rd!c0d0",
		exp_name	=> "rd/c0d0" ,
		rules		=> <<EOF
BUS=="scsi", NAME="%k"
KERNEL=="ttyUSB0", NAME="visor"
EOF
	},
	{
		desc		=> "name test with ! in the name, but no matching rule",
		subsys		=> "block",
		devpath		=> "/block/rd!c0d0",
		exp_name	=> "rd/c0d0" ,
		rules		=> <<EOF
KERNEL=="ttyUSB0", NAME="visor"
EOF
	},
	{
		desc		=> "name test with ! in the name for a partition",
		subsys		=> "block",
		devpath		=> "/block/cciss!c0d0/cciss!c0d0p1",
		exp_name	=> "cciss/c0d0p1" ,
		rules		=> <<EOF
BUS=="scsi", NAME="%k"
KERNEL=="ttyUSB0", NAME="visor"
EOF
	},
	{
		desc		=> "ID rule",
		subsys		=> "block",
		devpath		=> "/block/sda",
		exp_name	=> "scsi-0:0:0:0",
		rules		=> <<EOF
BUS=="usb", ID=="0:0:0:0", NAME="not-scsi"
BUS=="scsi", ID=="0:0:0:1", NAME="no-match"
BUS=="scsi", ID==":0", NAME="short-id"
BUS=="scsi", ID=="/0:0:0:0", NAME="no-match"
BUS=="scsi", ID=="0:0:0:0", NAME="scsi-0:0:0:0"
EOF
	},
	{
		desc		=> "ID wildcard all",
		subsys		=> "block",
		devpath		=> "/block/sda",
		exp_name	=> "scsi-0:0:0:0",
		rules		=> <<EOF
BUS=="scsi", ID=="*:1", NAME="no-match"
BUS=="scsi", ID=="*:0:1", NAME="no-match"
BUS=="scsi", ID=="*:0:0:1", NAME="no-match"
BUS=="scsi", ID=="*", NAME="scsi-0:0:0:0"
BUS=="scsi", ID=="0:0:0:0", NAME="bad"
EOF
	},
	{
		desc		=> "ID wildcard partial",
		subsys		=> "block",
		devpath		=> "/block/sda",
		exp_name	=> "scsi-0:0:0:0",
		rules		=> <<EOF
BUS=="scsi", ID=="*:0", NAME="scsi-0:0:0:0"
BUS=="scsi", ID=="0:0:0:0", NAME="bad"
EOF
	},
	{
		desc		=> "ID wildcard partial 2",
		subsys		=> "block",
		devpath		=> "/block/sda",
		exp_name	=> "scsi-0:0:0:0",
		rules		=> <<EOF
BUS=="scsi", ID=="*:0:0:0", NAME="scsi-0:0:0:0"
BUS=="scsi", ID=="0:0:0:0", NAME="bad"
EOF
	},
	{
		desc		=> "ignore SYSFS attribute whitespace",
		subsys		=> "block",
		devpath		=> "/block/sda",
		exp_name	=> "ignored",
		rules		=> <<EOF
BUS=="scsi", SYSFS{whitespace_test}=="WHITE  SPACE", NAME="ignored"
EOF
	},
	{
		desc		=> "do not ignore SYSFS attribute whitespace",
		subsys		=> "block",
		devpath		=> "/block/sda",
		exp_name	=> "matched-with-space",
		rules		=> <<EOF
BUS=="scsi", SYSFS{whitespace_test}=="WHITE  SPACE ", NAME="wrong-to-ignore"
BUS=="scsi", SYSFS{whitespace_test}=="WHITE  SPACE   ", NAME="matched-with-space"
EOF
	},
	{
		desc		=> "permissions USER=bad GROUP=name",
		subsys		=> "tty",
		devpath		=> "/class/tty/tty33",
		exp_name	=> "tty33",
		exp_perms	=> "0:0:0660",
		rules		=> <<EOF
KERNEL=="tty33", NAME="tty33", OWNER="bad", GROUP="name"
EOF
	},
	{
		desc		=> "permissions OWNER=5000",
		subsys		=> "block",
		devpath		=> "/block/sda",
		exp_name	=> "node",
		exp_perms	=> "5000::0660",
		rules		=> <<EOF
BUS=="scsi", KERNEL=="sda", NAME="node", OWNER="5000"
EOF
	},
	{
		desc		=> "permissions GROUP=100",
		subsys		=> "block",
		devpath		=> "/block/sda",
		exp_name	=> "node",
		exp_perms	=> ":100:0660",
		rules		=> <<EOF
BUS=="scsi", KERNEL=="sda", NAME="node", GROUP="100"
EOF
	},
	{
		desc		=> "textual user id",
		subsys		=> "block",
		devpath		=> "/block/sda",
		exp_name	=> "node",
		exp_perms	=> "nobody::0660",
		rules		=> <<EOF
BUS=="scsi", KERNEL=="sda", NAME="node", OWNER="nobody"
EOF
	},
	{
		desc		=> "textual group id",
		subsys		=> "block",
		devpath		=> "/block/sda",
		exp_name	=> "node",
		exp_perms	=> ":daemon:0660",
		rules		=> <<EOF
BUS=="scsi", KERNEL=="sda", NAME="node", GROUP="daemon"
EOF
	},
	{
		desc		=> "textual user/group id",
		subsys		=> "block",
		devpath		=> "/block/sda",
		exp_name	=> "node",
		exp_perms	=> "root:mail:0660",
		rules		=> <<EOF
BUS=="scsi", KERNEL=="sda", NAME="node", OWNER="root", GROUP="mail"
EOF
	},
	{
		desc		=> "permissions MODE=0777",
		subsys		=> "block",
		devpath		=> "/block/sda",
		exp_name	=> "node",
		exp_perms	=> "::0777",
		rules		=> <<EOF
BUS=="scsi", KERNEL=="sda", NAME="node", MODE="0777"
EOF
	},
	{
		desc		=> "permissions OWNER=5000 GROUP=100 MODE=0777",
		subsys		=> "block",
		devpath		=> "/block/sda",
		exp_name	=> "node",
		exp_perms	=> "5000:100:0777",
		rules		=> <<EOF
BUS=="scsi", KERNEL=="sda", NAME="node", OWNER="5000", GROUP="100", MODE="0777"
EOF
	},
	{
		desc		=> "permissions OWNER to 5000",
		subsys		=> "tty",
		devpath		=> "/class/tty/ttyUSB0",
		exp_name	=> "ttyUSB0",
		exp_perms	=> "5000::",
		rules		=> <<EOF
KERNEL=="ttyUSB[0-9]*", NAME="ttyUSB%n", OWNER="5000"
EOF
	},
	{
		desc		=> "permissions GROUP to 100",
		subsys		=> "tty",
		devpath		=> "/class/tty/ttyUSB0",
		exp_name	=> "ttyUSB0",
		exp_perms	=> ":100:0660",
		rules		=> <<EOF
KERNEL=="ttyUSB[0-9]*", NAME="ttyUSB%n", GROUP="100"
EOF
	},
	{
		desc		=> "permissions MODE to 0060",
		subsys		=> "tty",
		devpath		=> "/class/tty/ttyUSB0",
		exp_name	=> "ttyUSB0",
		exp_perms	=> "::0060",
		rules		=> <<EOF
KERNEL=="ttyUSB[0-9]*", NAME="ttyUSB%n", MODE="0060"
EOF
	},
	{
		desc		=> "permissions OWNER, GROUP, MODE",
		subsys		=> "tty",
		devpath		=> "/class/tty/ttyUSB0",
		exp_name	=> "ttyUSB0",
		exp_perms	=> "5000:100:0777",
		rules		=> <<EOF
KERNEL=="ttyUSB[0-9]*", NAME="ttyUSB%n", OWNER="5000", GROUP="100", MODE="0777"
EOF
	},
	{
		desc		=> "permissions only rule",
		subsys		=> "tty",
		devpath		=> "/class/tty/ttyUSB0",
		exp_name	=> "ttyUSB0",
		exp_perms	=> "5000:100:0777",
		rules		=> <<EOF
KERNEL=="ttyUSB[0-9]*", OWNER="5000", GROUP="100", MODE="0777"
KERNEL=="ttyUSX[0-9]*", OWNER="5001", GROUP="101", MODE="0444"
KERNEL=="ttyUSB[0-9]*", NAME="ttyUSB%n"
EOF
	},
	{
		desc		=> "multiple permissions only rule",
		subsys		=> "tty",
		devpath		=> "/class/tty/ttyUSB0",
		exp_name	=> "ttyUSB0",
		exp_perms	=> "3000:4000:0777",
		rules		=> <<EOF
SUBSYSTEM=="tty", OWNER="3000"
SUBSYSTEM=="tty", GROUP="4000"
SUBSYSTEM=="tty", MODE="0777"
KERNEL=="ttyUSX[0-9]*", OWNER="5001", GROUP="101", MODE="0444"
KERNEL=="ttyUSB[0-9]*", NAME="ttyUSB%n"
EOF
	},
	{
		desc		=> "permissions only rule with override at NAME rule",
		subsys		=> "tty",
		devpath		=> "/class/tty/ttyUSB0",
		exp_name	=> "ttyUSB0",
		exp_perms	=> "3000:8000:0777",
		rules		=> <<EOF
SUBSYSTEM=="tty", OWNER="3000"
SUBSYSTEM=="tty", GROUP="4000"
SUBSYSTEM=="tty", MODE="0777"
KERNEL=="ttyUSX[0-9]*", OWNER="5001", GROUP="101", MODE="0444"
KERNEL=="ttyUSB[0-9]*", NAME="ttyUSB%n", GROUP="8000"
EOF
	},
	{
		desc		=> "major/minor number test",
		subsys		=> "block",
		devpath		=> "/block/sda",
		exp_name	=> "node",
		exp_majorminor	=> "8:0",
		rules		=> <<EOF
BUS=="scsi", KERNEL=="sda", NAME="node"
EOF
	},
	{
		desc		=> "big minor number test",
		subsys		=> "i2c-dev",
		devpath		=> "/class/i2c-dev/i2c-300",
		exp_name	=> "node",
		exp_majorminor	=> "89:300",
		rules		=> <<EOF
KERNEL=="i2c-300", NAME="node"
EOF
	},
	{
		desc		=> "big major number test",
		subsys		=> "i2c-dev",
		devpath		=> "/class/i2c-dev/i2c-fake1",
		exp_name	=> "node",
		exp_majorminor	=> "4095:1",
		rules		=> <<EOF
KERNEL=="i2c-fake1", NAME="node"
EOF
	},
	{
		desc		=> "big major and big minor number test",
		subsys		=> "i2c-dev",
		devpath		=> "/class/i2c-dev/i2c-fake2",
		exp_name	=> "node",
		exp_majorminor	=> "4094:89999",
		rules		=> <<EOF
KERNEL=="i2c-fake2", NAME="node"
EOF
	},
	{
		desc		=> "multiple symlinks with format char",
		subsys		=> "tty",
		devpath		=> "/class/tty/ttyUSB0",
		exp_name	=> "symlink2-ttyUSB0",
		exp_target	=> "ttyUSB0",
		rules		=> <<EOF
KERNEL=="ttyUSB[0-9]*", NAME="ttyUSB%n", SYMLINK="symlink1-%n symlink2-%k symlink3-%b"
EOF
	},
	{
		desc		=> "symlink creation (same directory)",
		subsys		=> "tty",
		devpath		=> "/class/tty/ttyUSB0",
		exp_name	=> "visor0",
		exp_target	=> "ttyUSB0",
		rules		=> <<EOF
KERNEL=="ttyUSB[0-9]*", NAME="ttyUSB%n", SYMLINK="visor%n"
EOF
	},
	{
		desc		=> "symlink creation (relative link forward)",
		subsys		=> "block",
		devpath		=> "/block/sda/sda2",
		exp_name	=> "1/2/symlink" ,
		exp_target	=> "a/b/node",
		rules		=> <<EOF
BUS=="scsi", SYSFS{vendor}=="IBM-ESXS", NAME="1/2/a/b/node", SYMLINK="1/2/symlink"
EOF
	},
	{
		desc		=> "symlink creation (relative link back and forward)",
		subsys		=> "block",
		devpath		=> "/block/sda/sda2",
		exp_name	=> "1/2/c/d/symlink" ,
		exp_target	=> "../../a/b/node",
		rules		=> <<EOF
BUS=="scsi", SYSFS{vendor}=="IBM-ESXS", NAME="1/2/a/b/node", SYMLINK="1/2/c/d/symlink"
EOF
	},
	{
		desc		=> "multiple symlinks",
		subsys		=> "tty",
		devpath		=> "/class/tty/ttyUSB0",
		exp_name	=> "second-0" ,
		exp_target	=> "visor" ,
		rules		=> <<EOF
KERNEL=="ttyUSB0", NAME="visor", SYMLINK="first-%n second-%n third-%n"
EOF
	},
	{
		desc		=> "symlink only rule",
		subsys		=> "block",
		devpath		=> "/block/sda",
		exp_name	=> "symlink-only2",
		exp_target	=> "link",
		rules		=> <<EOF
BUS=="scsi", KERNEL=="sda", SYMLINK+="symlink-only1"
BUS=="scsi", KERNEL=="sda", SYMLINK+="symlink-only2"
BUS=="scsi", KERNEL=="sda", NAME="link", SYMLINK+="symlink0"
EOF
	},
	{
		desc		=> "symlink name '.'",
		subsys		=> "block",
		devpath		=> "/block/sda",
		exp_name	=> ".",
		exp_target	=> "link",
		exp_add_error	=> "yes",
		exp_rem_error	=> "yes",
		rules		=> <<EOF
BUS=="scsi", KERNEL=="sda", NAME="link", SYMLINK+="."
EOF
	},
	{
		desc		=> "symlink node to itself",
		subsys		=> "tty",
		devpath		=> "/class/tty/tty0",
		exp_name	=> "link",
		exp_target	=> "link",
		exp_rem_error	=> "yes",
		option		=> "clean",
		rules		=> <<EOF
KERNEL=="tty0", NAME="link", SYMLINK+="link"
EOF
	},
	{
		desc		=> "symlink %n substitution",
		subsys		=> "tty",
		devpath		=> "/class/tty/ttyUSB0",
		exp_name	=> "symlink0",
		exp_target	=> "ttyUSB0",
		rules		=> <<EOF
KERNEL=="ttyUSB[0-9]*", NAME="ttyUSB%n", SYMLINK+="symlink%n"
EOF
	},
	{
		desc		=> "symlink %k substitution",
		subsys		=> "tty",
		devpath		=> "/class/tty/ttyUSB0",
		exp_name	=> "symlink-ttyUSB0",
		exp_target	=> "ttyUSB0",
		rules		=> <<EOF
KERNEL=="ttyUSB[0-9]*", NAME="ttyUSB%n", SYMLINK+="symlink-%k"
EOF
	},
	{
		desc		=> "symlink %M:%m substitution",
		subsys		=> "tty",
		devpath		=> "/class/tty/ttyUSB0",
		exp_name	=> "major-188:0",
		exp_target	=> "ttyUSB0",
		rules		=> <<EOF
KERNEL=="ttyUSB[0-9]*", NAME="ttyUSB%n", SYMLINK+="major-%M:%m"
EOF
	},
	{
		desc		=> "symlink %b substitution",
		subsys		=> "block",
		devpath		=> "/block/sda",
		exp_name	=> "symlink-0:0:0:0",
		exp_target	=> "node",
		rules		=> <<EOF
BUS=="scsi", KERNEL=="sda", NAME="node", SYMLINK+="symlink-%b"
EOF
	},
	{
		desc		=> "symlink %c substitution",
		subsys		=> "tty",
		devpath		=> "/class/tty/ttyUSB0",
		exp_name	=> "test",
		exp_target	=> "ttyUSB0",
		rules		=> <<EOF
KERNEL=="ttyUSB[0-9]*", PROGRAM=="/bin/echo test" NAME="ttyUSB%n", SYMLINK+="%c"
EOF
	},
	{
		desc		=> "symlink %c{N} substitution",
		subsys		=> "tty",
		devpath		=> "/class/tty/ttyUSB0",
		exp_name	=> "test",
		exp_target	=> "ttyUSB0",
		rules		=> <<EOF
KERNEL=="ttyUSB[0-9]*", PROGRAM=="/bin/echo symlink test this" NAME="ttyUSB%n", SYMLINK+="%c{2}"
EOF
	},
	{
		desc		=> "symlink %c{N+} substitution",
		subsys		=> "tty",
		devpath		=> "/class/tty/ttyUSB0",
		exp_name	=> "this",
		exp_target	=> "ttyUSB0",
		rules		=> <<EOF
KERNEL=="ttyUSB[0-9]*", PROGRAM=="/bin/echo symlink test this" NAME="ttyUSB%n", SYMLINK+="%c{2+}"
EOF
	},
	{
		desc		=> "symlink only rule with %c{N+}",
		subsys		=> "block",
		devpath		=> "/block/sda",
		exp_name	=> "test",
		exp_target	=> "link",
		rules		=> <<EOF
BUS=="scsi", KERNEL=="sda", PROGRAM=="/bin/echo link test this" SYMLINK+="%c{2+}"
BUS=="scsi", KERNEL=="sda", NAME="link", SYMLINK+="symlink0"
EOF
	},
	{
		desc		=> "symlink %s{filename} substitution",
		subsys		=> "tty",
		devpath		=> "/class/tty/ttyUSB0",
		exp_name	=> "188:0",
		exp_target	=> "ttyUSB0",
		rules		=> <<EOF
KERNEL=="ttyUSB[0-9]*", NAME="ttyUSB%n", SYMLINK+="%s{dev}"
EOF
	},
	{
		desc		=> "symlink %Ns{filename} substitution",
		subsys		=> "tty",
		devpath		=> "/class/tty/ttyUSB0",
		exp_name	=> "188",
		exp_target	=> "ttyUSB0",
		rules		=> <<EOF
KERNEL=="ttyUSB[0-9]*", NAME="ttyUSB%n", SYMLINK+="%3s{dev}"
EOF
	},
	{
		desc		=> "symlink with '%' in name",
		subsys		=> "tty",
		devpath		=> "/class/tty/ttyUSB0",
		exp_name	=> "percent%sign",
		exp_target	=> "ttyUSB0",
		rules		=> <<EOF
KERNEL=="ttyUSB[0-9]*", NAME="ttyUSB%n", SYMLINK+="percent%%sign"
EOF
	},
	{
		desc		=> "symlink with '%' in name",
		subsys		=> "tty",
		devpath		=> "/class/tty/ttyUSB0",
		exp_name	=> "%ttyUSB0_name",
		exp_target	=> "ttyUSB0",
		rules		=> <<EOF
KERNEL=="ttyUSB[0-9]*", NAME="ttyUSB%n", SYMLINK+="%%%k_name"
EOF
	},
	{
		desc		=> "program result substitution (numbered part of)",
		subsys		=> "block",
		devpath		=> "/block/sda/sda3",
		exp_name	=> "link1",
		exp_target	=> "node",
		rules		=> <<EOF
BUS=="scsi", PROGRAM=="/bin/echo -n node link1 link2", RESULT=="node *", NAME="%c{1}", SYMLINK+="%c{2} %c{3}"
EOF
	},
	{
		desc		=> "program result substitution (numbered part of+)",
		subsys		=> "block",
		devpath		=> "/block/sda/sda3",
		exp_name	=> "link4",
		exp_target	=> "node",
		rules		=> <<EOF
BUS=="scsi", PROGRAM=="/bin/echo -n node link1 link2 link3 link4", RESULT=="node *", NAME="%c{1}", SYMLINK+="%c{2+}"
EOF
	},
	{
		desc		=> "enumeration char test (single test)",
		subsys		=> "block",
		devpath		=> "/block/sda",
		exp_name	=> "cdrom",
		rules		=> <<EOF
KERNEL=="sda", NAME="cdrom%e"
EOF
	},
	{
		desc		=> "enumeration char test sequence 1/5 (keep)",
		subsys		=> "block",
		devpath		=> "/block/sda",
		exp_name	=> "cdrom",
		option		=> "keep",
		rules		=> <<EOF
KERNEL=="sda", NAME="cdrom%e"
EOF
	},
	{
		desc		=> "enumeration char test sequence 2/5 (keep)",
		subsys		=> "block",
		devpath		=> "/block/sda/sda1",
		exp_name	=> "enum",
		option		=> "keep",
		rules		=> <<EOF
KERNEL=="sda1", NAME="enum%e"
EOF
	},
	{
		desc		=> "enumeration char test sequence 3/5 (keep)",
		subsys		=> "block",
		devpath		=> "/block/sda/sda2",
		exp_name	=> "cdrom1",
		option		=> "keep",
		rules		=> <<EOF
KERNEL=="sda2", NAME="cdrom%e"
EOF
	},
	{
		desc		=> "enumeration char test sequence 4/5 (keep)",
		subsys		=> "block",
		devpath		=> "/block/sda/sda3",
		exp_name	=> "enum1",
		option		=> "keep",
		rules		=> <<EOF
KERNEL=="sda3", NAME="enum%e"
EOF
	},
	{
		desc		=> "enumeration char test sequence 5/5 (clean)",
		subsys		=> "block",
		devpath		=> "/block/sda/sda4",
		exp_name	=> "cdrom2",
		option		=> "clean",
		rules		=> <<EOF
KERNEL=="sda4", NAME="cdrom%e"
EOF
	},
	{
		desc		=> "enumeration char test after cleanup (single test)",
		subsys		=> "block",
		devpath		=> "/block/sda",
		exp_name	=> "cdrom",
		rules		=> <<EOF
KERNEL=="sda", NAME="cdrom%e"
EOF
	},
	{
		desc		=> "ignore rule test",
		subsys		=> "block",
		devpath		=> "/block/sda",
		exp_name	=> "node",
		exp_add_error	=> "yes",
		rules		=> <<EOF
BUS=="scsi", KERNEL=="sda", NAME="node", OPTIONS="ignore"
EOF
	},
	{
		desc		=> "all_partitions, option-only rule",
		subsys		=> "block",
		devpath		=> "/block/sda",
		exp_name	=> "node6",
		rules		=> <<EOF
SUBSYSTEM=="block", OPTIONS="all_partitions"
BUS=="scsi", KERNEL=="sda", NAME="node"
EOF
	},
	{
		desc		=> "all_partitions, option-only rule (fail on partition)",
		subsys		=> "block",
		devpath		=> "/block/sda/sda1",
		exp_name	=> "node6",
		exp_add_error	=> "yes",
		rules		=> <<EOF
SUBSYSTEM=="block", OPTIONS="all_partitions"
BUS=="scsi", KERNEL=="sda", NAME="node"
EOF
	},
	{
		desc		=> "ignore remove event test",
		subsys		=> "block",
		devpath		=> "/block/sda",
		exp_name	=> "node",
		exp_rem_error	=> "yes",
		rules		=> <<EOF
BUS=="scsi", KERNEL=="sda", NAME="node", OPTIONS="ignore_remove"
EOF
	},
	{
		desc		=> "ignore remove event test (with all partitions)",
		subsys		=> "block",
		devpath		=> "/block/sda",
		exp_name	=> "node14",
		exp_rem_error	=> "yes",
		option		=> "clean",
		rules		=> <<EOF
BUS=="scsi", KERNEL=="sda", NAME="node", OPTIONS="ignore_remove, all_partitions"
EOF
	},
	{
		desc		=> "SUBSYSTEM match test",
		subsys		=> "block",
		devpath		=> "/block/sda",
		exp_name	=> "node",
		rules		=> <<EOF
BUS=="scsi", KERNEL=="sda", NAME="should_not_match", SUBSYSTEM=="vc"
BUS=="scsi", KERNEL=="sda", NAME="node", SUBSYSTEM=="block"
BUS=="scsi", KERNEL=="sda", NAME="should_not_match2", SUBSYSTEM=="vc"
EOF
	},
	{
		desc		=> "DRIVER match test",
		subsys		=> "block",
		devpath		=> "/block/sda",
		exp_name	=> "node",
		rules		=> <<EOF
BUS=="scsi", KERNEL=="sda", NAME="should_not_match", DRIVER=="sd-wrong"
BUS=="scsi", KERNEL=="sda", NAME="node", DRIVER=="sd"
EOF
	},
	{
		desc		=> "temporary node creation test",
		subsys		=> "block",
		devpath		=> "/block/sda",
		exp_name	=> "node",
		rules		=> <<EOF
BUS=="scsi", KERNEL=="sda", PROGRAM=="/usr/bin/test -b %N" NAME="node"
EOF
	},
	{
		desc		=> "devpath substitution test",
		subsys		=> "block",
		devpath		=> "/block/sda",
		exp_name	=> "sda",
		rules		=> <<EOF
BUS=="scsi", KERNEL=="sda", PROGRAM=="/bin/echo %p", RESULT=="/block/sda" NAME="%k"
EOF
	},
	{
		desc		=> "parent node name substitution test sequence 1/2 (keep)",
		subsys		=> "block",
		devpath		=> "/block/sda",
		exp_name	=> "main_device",
		option		=> "keep",
		rules		=> <<EOF
BUS=="scsi", KERNEL=="sda", NAME="main_device"
EOF
	},
	{
		desc		=> "parent node name substitution test sequence 2/2 (clean)",
		subsys		=> "block",
		devpath		=> "/block/sda/sda1",
		exp_name	=> "main_device-part-1",
		option		=> "clean",
		rules		=> <<EOF
BUS=="scsi", KERNEL=="sda1", NAME="%P-part-1"
EOF
	},
	{
		desc		=> "udev_root substitution",
		subsys		=> "block",
		devpath		=> "/block/sda/sda1",
		exp_name	=> "start-udev-root-end",
		rules		=> <<EOF
BUS=="scsi", KERNEL=="sda1", NAME="start-%r-end"
EOF
	},
	{
		desc		=> "last_rule option",
		subsys		=> "block",
		devpath		=> "/block/sda/sda1",
		exp_name	=> "last",
		rules		=> <<EOF
BUS=="scsi", KERNEL=="sda1", SYMLINK+="last", OPTIONS="last_rule"
BUS=="scsi", KERNEL=="sda1", NAME="very-last"
EOF
	},
	{
		desc		=> "negation KERNEL!=",
		subsys		=> "block",
		devpath		=> "/block/sda/sda1",
		exp_name	=> "match",
		rules		=> <<EOF
BUS=="scsi", KERNEL!="sda1", NAME="matches-but-is-negated"
BUS=="scsi", KERNEL!="xsda1", NAME="match"
BUS=="scsi", KERNEL=="sda1", NAME="wrong"
EOF
	},
	{
		desc		=> "negation SUBSYSTEM!=",
		subsys		=> "block",
		devpath		=> "/block/sda/sda1",
		exp_name	=> "not-anything",
		rules		=> <<EOF
BUS=="scsi", SUBSYSTEM=="block", KERNEL!="sda1", NAME="matches-but-is-negated"
BUS=="scsi", SUBSYSTEM!="anything", NAME="not-anything"
BUS=="scsi", KERNEL=="sda1", NAME="wrong"
EOF
	},
	{
		desc		=> "negation PROGRAM!= exit code",
		subsys		=> "block",
		devpath		=> "/block/sda/sda1",
		exp_name	=> "nonzero-program",
		rules		=> <<EOF
KERNEL=="sda1", PROGRAM!="/bin/false", NAME="nonzero-program"
BUS=="scsi", KERNEL=="sda1", NAME="wrong"
EOF
	},
	{
		desc		=> "test for whitespace between the operator",
		subsys		=> "block",
		devpath		=> "/block/sda/sda1",
		exp_name	=> "true",
		rules		=> <<EOF
KERNEL   ==   "sda1"     ,    NAME   =    "true"
BUS=="scsi", KERNEL=="sda1", NAME="wrong"
EOF
	},
	{
		desc		=> "ENV{} test",
		subsys		=> "block",
		devpath		=> "/block/sda/sda1",
		exp_name	=> "true",
		rules		=> <<EOF
BUS=="scsi", KERNEL=="sda1", ENV{ENV_KEY_TEST}=="go", NAME="wrong"
BUS=="scsi", KERNEL=="sda1", ENV{ENV_KEY_TEST}=="test", NAME="true"
BUS=="scsi", KERNEL=="sda1", ENV{ENV_KEY_TEST}=="bad", NAME="bad"
EOF
	},
	{
		desc		=> "ENV{} test",
		subsys		=> "block",
		devpath		=> "/block/sda/sda1",
		exp_name	=> "true",
		rules		=> <<EOF
BUS=="scsi", KERNEL=="sda1", ENV{ENV_KEY_TEST}=="go", NAME="wrong"
BUS=="scsi", KERNEL=="sda1", ENV{ENV_KEY_TEST}=="yes", ENV{ACTION}=="add", ENV{DEVPATH}=="/block/sda/sdax1", NAME="no"
BUS=="scsi", KERNEL=="sda1", ENV{ENV_KEY_TEST}=="test", ENV{ACTION}=="add", ENV{DEVPATH}=="/block/sda/sda1", NAME="true"
BUS=="scsi", KERNEL=="sda1", ENV{ENV_KEY_TEST}=="bad", NAME="bad"
EOF
	},
	{
		desc		=> "untrusted string sanitize",
		subsys		=> "block",
		devpath		=> "/block/sda/sda1",
		exp_name	=> "sane",
		rules		=> <<EOF
BUS=="scsi", KERNEL=="sda1", PROGRAM=="/bin/echo -e name; (/sbin/badprogram)", RESULT="name_ _/sbin/badprogram_", NAME="sane"
EOF
	},
	{
		desc		=> "read sysfs value from device down in the chain",
		subsys		=> "block",
		devpath		=> "/class/tty/ttyUSB0",
		exp_name	=> "serial-0000:00:09.0",
		rules		=> <<EOF
KERNEL=="ttyUSB*", NAME="serial-%s{serial}"
EOF
	},
	{
		desc		=> "match against empty key string",
		subsys		=> "block",
		devpath		=> "/block/sda",
		exp_name	=> "ok",
		rules		=> <<EOF
KERNEL=="sda", SYSFS{nothing}!="", NAME="not-1-ok"
KERNEL=="sda", SYSFS{nothing}=="", NAME="not-2-ok"
KERNEL=="sda", SYSFS{vendor}!="", NAME="ok"
KERNEL=="sda", SYSFS{vendor}=="", NAME="not-3-ok"
EOF
	},
	{
		desc		=> "check ACTION value",
		subsys		=> "block",
		devpath		=> "/block/sda",
		exp_name	=> "ok",
		rules		=> <<EOF
ACTION=="unknown", KERNEL=="sda", NAME="unknown-not-ok"
ACTION=="add", KERNEL=="sda", NAME="ok"
EOF
	},
	{
		desc		=> "apply NAME only once",
		subsys		=> "block",
		devpath		=> "/block/sda",
		exp_name	=> "link",
		exp_target	=> "ok",
		rules		=> <<EOF
KERNEL=="sda", NAME="ok"
KERNEL=="sda", NAME="not-ok"
KERNEL=="sda", SYMLINK+="link"
EOF
	},
	{
		desc		=> "test RUN key",
		subsys		=> "block",
		devpath		=> "/block/sda",
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
		devpath		=> "/block/sda",
		exp_name	=> "testsymlink",
		exp_target	=> "ok",
		exp_rem_error	=> "yes",
		option		=> "clean",
		rules		=> <<EOF
KERNEL=="sda", NAME="ok", RUN+="/bin/sh -c 'ln -s `basename \$\$DEVNAME` %r/testsymlink'"
KERNEL=="sda", NAME="not-ok"
EOF
	},
	{
		desc		=> "test RUN key remove",
		subsys		=> "block",
		devpath		=> "/block/sda",
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
		devpath		=> "/block/sda",
		exp_name	=> "ok",
		exp_perms	=> "root:nobody:0640",
		rules		=> <<EOF
KERNEL=="sda", GROUP:="nobody"
KERNEL=="sda", GROUP="not-ok", MODE="0640", NAME="ok"
EOF
	},
	{
		desc		=> "final assignment",
		subsys		=> "block",
		devpath		=> "/block/sda",
		exp_name	=> "ok",
		exp_perms	=> "root:nobody:0640",
		rules		=> <<EOF
KERNEL=="sda", GROUP:="nobody"
SUBSYSTEM=="block", MODE:="640"
KERNEL=="sda", GROUP="not-ok", MODE="0666", NAME="ok"
EOF
	},
	{
		desc		=> "env substitution",
		subsys		=> "block",
		devpath		=> "/block/sda",
		exp_name	=> "node-add-me",
		rules		=> <<EOF
KERNEL=="sda", MODE="0666", NAME="node-\$env{ACTION}-me"
EOF
	},
	{
		desc		=> "reset list to current value",
		subsys		=> "tty",
		devpath		=> "/class/tty/ttyUSB0",
		exp_name	=> "three",
		not_exp_name	=> "two",
		exp_target	=> "node",
		rules		=> <<EOF
KERNEL=="ttyUSB[0-9]*", SYMLINK+="one"
KERNEL=="ttyUSB[0-9]*", SYMLINK+="two"
KERNEL=="ttyUSB[0-9]*", SYMLINK="three"
KERNEL=="ttyUSB[0-9]*", NAME="node"
EOF
	},
);

# set env
$ENV{ENV_KEY_TEST} = "test";
$ENV{SYSFS_PATH} = $sysfs;
$ENV{UDEV_CONFIG_FILE} = $udev_conf;
$ENV{UDEV_NO_DEVD} = "yes";
$ENV{UDEV_NO_HOTPLUGD} = "yes";


sub udev {
	my ($action, $subsys, $devpath, $rules) = @_;

	$ENV{DEVPATH} = $devpath;

	# create temporary rules
	open CONF, ">$udev_rules" || die "unable to create rules file: $udev_rules";
	print CONF $$rules;
	close CONF;

	$ENV{ACTION} = $action;
	system("$udev_bin $subsys");
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

sub run_test {
	my ($rules, $number) = @_;

	print "TEST $number: $rules->{desc}\n";

	if ($rules->{exp_target}) {
		print "device \'$rules->{devpath}\' expecting symlink '$rules->{exp_name}' to node \'$rules->{exp_target}\'\n";
	} else {
		print "device \'$rules->{devpath}\' expecting node \'$rules->{exp_name}\'\n";
	}


	udev("add", $rules->{subsys}, $rules->{devpath}, \$rules->{rules});
	if ((-e "$PWD/$udev_root$rules->{exp_name}") ||
	    (-l "$PWD/$udev_root$rules->{exp_name}")) {

		my ($dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size,
		    $atime, $mtime, $ctime, $blksize, $blocks) = stat("$PWD/$udev_root$rules->{exp_name}");

		if (defined($rules->{not_exp_name})) {
			if ((-e "$PWD/$udev_root$rules->{not_exp_name}") ||
			    (-l "$PWD/$udev_root$rules->{not_exp_name}")) {
				print "nonexistent: error \'$rules->{not_exp_name}\' not expected to be there\n";
				$error++
			}
		}
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
		system("rm -rf $udev_db");
		system("rm -rf $udev_root");
		mkdir($udev_root) || die "unable to create udev_root: $udev_root\n";
	}

}

# only run if we have root permissions
# due to mknod restrictions
if (!($<==0)) {
	print "Must have root permissions to run properly.\n";
	exit;
}

# prepare
system("rm -rf $udev_root");
mkdir($udev_root) || die "unable to create udev_root: $udev_root\n";

# create config file
open CONF, ">$udev_conf" || die "unable to create config file: $udev_conf";
print CONF "udev_root=\"$udev_root\"\n";
print CONF "udev_db=\"$udev_db\"\n";
print CONF "udev_rules=\"$udev_rules\"\n";
close CONF;

my $test_num = 1;

if ($ARGV[0]) {
	# only run one test
	$test_num = $ARGV[0];

	if (defined($tests[$test_num-1]->{desc})) {
		print "udev-test will run test number $test_num only:\n\n";
		run_test($tests[$test_num-1], $test_num);
	} else {
		print "test does not exist.\n";
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
system("rm -rf $udev_db");
system("rm -rf $udev_root");
unlink($udev_rules);
unlink($udev_conf);

