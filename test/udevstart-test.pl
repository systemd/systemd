#!/usr/bin/perl

# udevstart-test
#
# runs udevstart in a temporary directory with our test sysfs-tree
# and counts the created nodes to compare it with the expected numbers.
#
# Kay Sievers <kay.sievers@vrfy.org>, 2005
#

use warnings;
use strict;

my $PWD = $ENV{PWD};
my $sysfs     = "sys/";
my $udev_bin  = "../udev";
my $udev_root = "udev-root/"; # !!! directory will be removed !!!
my $udev_db   = ".udevdb";
my $main_conf = "udev-test.conf";
my $conf_tmp  = "udev-test.rules";

# set env
$ENV{UDEV_TEST} = "yes";
$ENV{SYSFS_PATH} = $sysfs;
$ENV{UDEV_CONFIG_FILE} = $main_conf;
$ENV{UDEV_NO_DEVD} = "yes";
$ENV{UDEV_NO_HOTPLUGD} = "yes";

# due to mknod restrictions
if (!($<==0)) {
	print "Must have root permissions to run properly.\n";
	exit;
}

# prepare
system("rm -rf $udev_root");
mkdir($udev_root) || die "unable to create udev_root: $udev_root\n";

# create initial config file
open CONF, ">$main_conf" || die "unable to create config file: $main_conf";
print CONF "udev_root=\"$udev_root\"\n";
print CONF "udev_db=\"$udev_db\"\n";
print CONF "udev_rules=\"$conf_tmp\"\n";
close CONF;

system("$udev_bin udevstart");
my $block = int( `find $udev_root -type b -print | wc -l`);
my $char  = int( `find $udev_root -type c -print | wc -l`);

print "block devices: $block/10\n";
print "char devices: $char/91\n";

# cleanup
system("rm -rf $udev_db");
system("rm -rf $udev_root");
unlink($conf_tmp);
unlink($main_conf);

