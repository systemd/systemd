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
my $udevstart_bin  = "../udevstart";
my $udev_root = "udev-root/"; # !!! directory will be removed !!!
my $udev_db   = ".udevdb";
my $udev_conf = "udev-test.conf";
my $udev_rules  = "udev-test.rules";

# set env
$ENV{SYSFS_PATH} = $sysfs;
$ENV{UDEV_CONFIG_FILE} = $udev_conf;

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

# create rules file
open RULES, ">$udev_rules" || die "unable to create rules file: $udev_rules";
print RULES "\n";
close RULES;

system("$udevstart_bin");
my $block = int(`find $udev_root -type b -print | wc -l`);
my $char  = int(`find $udev_root -type c -print | wc -l`);

print "block devices: $block/10\n";
print "char devices: $char/91\n";
print "\n";

# cleanup
system("rm -rf $udev_db");
system("rm -rf $udev_root");
unlink($udev_rules);
unlink($udev_conf);

