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
# udev reads the config, looks at the provided sysfs and
# first creates and then removes the device node.
# After creation and removal the result is checked against the
# expected value and the result is printed.
#
# happy testing,
# Kay Sievers <kay.sievers@vrfy.org>, 2003


use warnings;
use strict;

my $PWD = $ENV{PWD};
my $sysfs     = "sys/";
my $udev_bin  = "../udev";
my $udev_root = "udev-root/"; # !!! directory will be removed !!!
my $udev_db   = ".udev.tdb";
my $perm      = "udev.permissions";
my $main_conf = "udev-test.conf";
my $conf_tmp  = "udev-test.rules";


my @tests = (
	{
		desc     => "label test of scsi disc",
		subsys   => "block",
		devpath  => "block/sda",
		expected => "boot_disk" ,
		conf     => <<EOF
LABEL, BUS="scsi", SYSFS_vendor="IBM-ESXS", NAME="boot_disk%n"
REPLACE, KERNEL="ttyUSB0", NAME="visor"
EOF
	},
	{
		desc     => "label test of scsi partition",
		subsys   => "block",
		devpath  => "block/sda/sda1",
		expected => "boot_disk1" ,
		conf     => <<EOF
LABEL, BUS="scsi", SYSFS_vendor="IBM-ESXS", NAME="boot_disk%n"
EOF
	},
	{
		desc     => "label test of pattern match",
		subsys   => "block",
		devpath  => "block/sda/sda1",
		expected => "boot_disk1" ,
		conf     => <<EOF
LABEL, BUS="scsi", SYSFS_vendor="?IBM-ESXS", NAME="boot_disk%n-1"
LABEL, BUS="scsi", SYSFS_vendor="IBM-ESXS?", NAME="boot_disk%n-2"
LABEL, BUS="scsi", SYSFS_vendor="IBM-ES??", NAME="boot_disk%n"
LABEL, BUS="scsi", SYSFS_vendor="IBM-ESXSS", NAME="boot_disk%n-3"
EOF
	},
	{
		desc     => "catch device by *",
		subsys   => "tty",
		devpath  => "class/tty/ttyUSB0",
		expected => "visor/0" ,
		conf     => <<EOF
REPLACE, KERNEL="ttyUSB*", NAME="visor/%n"
EOF
	},
	{
		desc     => "catch device by ?",
		subsys   => "tty",
		devpath  => "class/tty/ttyUSB0",
		expected => "visor/0" ,
		conf     => <<EOF
REPLACE, KERNEL="ttyUSB??*", NAME="visor/%n-1"
REPLACE, KERNEL="ttyUSB??", NAME="visor/%n-2"
REPLACE, KERNEL="ttyUSB?", NAME="visor/%n"
EOF
	},
	{
		desc     => "catch device by character class",
		subsys   => "tty",
		devpath  => "class/tty/ttyUSB0",
		expected => "visor/0" ,
		conf     => <<EOF
REPLACE, KERNEL="ttyUSB[A-Z]*", NAME="visor/%n-1"
REPLACE, KERNEL="ttyUSB?[0-9]", NAME="visor/%n-2"
REPLACE, KERNEL="ttyUSB[0-9]*", NAME="visor/%n"
EOF
	},
	{
		desc     => "replace kernel name",
		subsys   => "tty",
		devpath  => "class/tty/ttyUSB0",
		expected => "visor" ,
		conf     => <<EOF
REPLACE, KERNEL="ttyUSB0", NAME="visor"
EOF
	},
	{
		desc     => "subdirectory handling",
		subsys   => "tty",
		devpath  => "class/tty/ttyUSB0",
		expected => "sub/direct/ory/visor" ,
		conf     => <<EOF
REPLACE, KERNEL="ttyUSB0", NAME="sub/direct/ory/visor"
EOF
	},
	{
		desc     => "place on bus of scsi partition",
		subsys   => "block",
		devpath  => "block/sda/sda3",
		expected => "first_disk3" ,
		conf     => <<EOF
TOPOLOGY, BUS="scsi", PLACE="0:0:0:0", NAME="first_disk%n"
EOF
	},
	{
		desc     => "test NAME substitution chars",
		subsys   => "block",
		devpath  => "block/sda/sda3",
		expected => "Major:8:minor:3:kernelnumber:3:bus:0:0:0:0" ,
		conf     => <<EOF
TOPOLOGY, BUS="scsi", PLACE="0:0:0:0", NAME="Major:%M:minor:%m:kernelnumber:%n:bus:%b"
EOF
	},
	{
		desc     => "callout result substitution",
		subsys   => "block",
		devpath  => "block/sda/sda3",
		expected => "special-device-3" ,
		conf     => <<EOF
CALLOUT, BUS="scsi", PROGRAM="/bin/echo -n special-device", ID="-special-*", NAME="%c-1-%n"
CALLOUT, BUS="scsi", PROGRAM="/bin/echo -n special-device", ID="special--*", NAME="%c-2-%n"
CALLOUT, BUS="scsi", PROGRAM="/bin/echo -n special-device", ID="special-device-", NAME="%c-3-%n"
CALLOUT, BUS="scsi", PROGRAM="/bin/echo -n special-device", ID="special-devic", NAME="%c-4-%n"
CALLOUT, BUS="scsi", PROGRAM="/bin/echo -n special-device", ID="special-*", NAME="%c-%n"
EOF
	},
	{
		desc     => "callout program substitution",
		subsys   => "block",
		devpath  => "block/sda/sda3",
		expected => "test-0:0:0:0" ,
		conf     => <<EOF
CALLOUT, BUS="scsi", PROGRAM="/bin/echo -n test-%b", ID="test-*", NAME="%c"
EOF
	},
	{
		desc     => "callout program substitution (numbered part of)",
		subsys   => "block",
		devpath  => "block/sda/sda3",
		expected => "link1" ,
		conf     => <<EOF
CALLOUT, BUS="scsi", PROGRAM="/bin/echo -n node link1 link2", ID="node *", NAME="%1c", SYMLINK="%2c %3c"
EOF
	},
	{
		desc     => "devfs disk naming substitution",
		subsys   => "block",
		devpath  => "block/sda",
		expected => "lun0/disc" ,
		conf     => <<EOF
LABEL, BUS="scsi", SYSFS_vendor="IBM-ESXS", NAME="lun0/%D"
EOF
	},
	{
		desc     => "devfs disk naming substitution",
		subsys   => "block",
		devpath  => "block/sda/sda2",
		expected => "lun0/part2" ,
		conf     => <<EOF
LABEL, BUS="scsi", SYSFS_vendor="IBM-ESXS", NAME="lun0/%D"
EOF
	},
	{
		desc     => "callout bus type",
		subsys   => "block",
		devpath  => "block/sda",
		expected => "scsi-0:0:0:0" ,
		conf     => <<EOF
CALLOUT, BUS="usb", PROGRAM="/bin/echo -n usb-%b", ID="*", NAME="%c"
CALLOUT, BUS="scsi", PROGRAM="/bin/echo -n scsi-%b", ID="*", NAME="%c"
CALLOUT, BUS="foo", PROGRAM="/bin/echo -n foo-%b", ID="*", NAME="%c"
EOF
	},
	{
		desc     => "symlink creation (same directory)",
		subsys   => "tty",
		devpath  => "class/tty/ttyUSB0",
		expected => "visor0" ,
		conf     => <<EOF
REPLACE, KERNEL="ttyUSB[0-9]*", NAME="ttyUSB%n", SYMLINK="visor%n"
EOF
	},
	{
		desc     => "symlink creation (relative link back)",
		subsys   => "block",
		devpath  => "block/sda/sda2",
		expected => "1/2/a/b/symlink" ,
		conf     => <<EOF
LABEL, BUS="scsi", SYSFS_vendor="IBM-ESXS", NAME="1/2/node", SYMLINK="1/2/a/b/symlink"
EOF
	},
	{
		desc     => "symlink creation (relative link forward)",
		subsys   => "block",
		devpath  => "block/sda/sda2",
		expected => "1/2/symlink" ,
		conf     => <<EOF
LABEL, BUS="scsi", SYSFS_vendor="IBM-ESXS", NAME="1/2/a/b/node", SYMLINK="1/2/symlink"
EOF
	},
	{
		desc     => "symlink creation (relative link back and forward)",
		subsys   => "block",
		devpath  => "block/sda/sda2",
		expected => "1/2/c/d/symlink" ,
		conf     => <<EOF
LABEL, BUS="scsi", SYSFS_vendor="IBM-ESXS", NAME="1/2/a/b/node", SYMLINK="1/2/c/d/symlink"
EOF
	},
	{
		desc     => "multiple symlinks",
		subsys   => "tty",
		devpath  => "class/tty/ttyUSB0",
		expected => "second-0" ,
		conf     => <<EOF
REPLACE, KERNEL="ttyUSB0", NAME="visor", SYMLINK="first-%n second-%n third-%n"
EOF
	},
);

# set env
$ENV{UDEV_TEST} = "yes";
$ENV{SYSFS_PATH} = $sysfs;
$ENV{UDEV_CONFIG_FILE} = $main_conf;


sub udev {
	my ($action, $subsys, $devpath, $config) = @_;

	$ENV{DEVPATH} = $devpath;

	# create temporary config
	open CONF, ">$conf_tmp" || die "unable to create config file: $conf_tmp";
	print CONF $$config;
	close CONF;

	$ENV{ACTION} = $action;
	system("$udev_bin $subsys");
}


# prepare
system("rm -rf $udev_root");
mkdir($udev_root) || die "unable to create udev_root: $udev_root\n";

# test
my $error = 0;
print "\nudev-test will run ".($#tests + 1)." tests:\n\n";

# create initial config file
open CONF, ">$main_conf" || die "unable to create config file: $main_conf";
print CONF "udev_root=\"$udev_root\"\n";
print CONF "udev_db=\"$udev_db\"\n";
print CONF "udev_rules=\"$conf_tmp\"\n";
print CONF "udev_permissions=\"$perm\"\n";
close CONF;

foreach my $config (@tests) {
	$config->{conf} =~ m/^([A-Z]*).*/;
	my $method  = $1;

	print "TEST: $config->{desc}\n";
	print "method \'$method\' for \'$config->{devpath}\' expecting node \'$config->{expected}\'\n";

	udev("add", $config->{subsys}, $config->{devpath}, \$config->{conf});
	if (-e "$PWD/$udev_root$config->{expected}") {
		print "add: ok    ";
	} else {
		print "add: error\n";
		system("tree $udev_root");
		print "\n";
		$error++;
	}

	udev("remove", $config->{subsys}, $config->{devpath}, \$config->{conf});
	if ((-e "$PWD/$udev_root$config->{expected}") ||
	    (-l "$PWD/$udev_root$config->{expected}")) {
		print "remove: error\n\n";
		system("tree $udev_root");
		$error++;
	} else {
		print "remove: ok\n\n";
	}
}

print "$error errors occured\n\n";

# cleanup
unlink($udev_db);
system("rm -rf $udev_root");
unlink($conf_tmp);
unlink($main_conf);

