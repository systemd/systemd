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
		desc		=> "label test of scsi disc",
		subsys		=> "block",
		devpath		=> "block/sda",
		exp_name=> "boot_disk" ,
		conf		=> <<EOF
BUS="scsi", SYSFS{vendor}="IBM-ESXS", NAME="boot_disk%n"
KERNEL="ttyUSB0", NAME="visor"
EOF
	},
	{
		desc		=> "label test of scsi partition",
		subsys		=> "block",
		devpath		=> "block/sda/sda1",
		exp_name=> "boot_disk1" ,
		conf		=> <<EOF
BUS="scsi", SYSFS{vendor}="IBM-ESXS", NAME="boot_disk%n"
EOF
	},
	{
		desc		=> "label test of pattern match",
		subsys		=> "block",
		devpath		=> "block/sda/sda1",
		exp_name=> "boot_disk1" ,
		conf		=> <<EOF
BUS="scsi", SYSFS{vendor}="?IBM-ESXS", NAME="boot_disk%n-1"
BUS="scsi", SYSFS{vendor}="IBM-ESXS?", NAME="boot_disk%n-2"
BUS="scsi", SYSFS{vendor}="IBM-ES??", NAME="boot_disk%n"
BUS="scsi", SYSFS{vendor}="IBM-ESXSS", NAME="boot_disk%n-3"
EOF
	},
	{
		desc		=> "label test of multiple sysfs files",
		subsys		=> "block",
		devpath		=> "block/sda/sda1",
		exp_name	=> "boot_disk1" ,
		conf		=> <<EOF
BUS="scsi", SYSFS{vendor}="IBM-ESXS", SYSFS{model}="ST336605LW   !#", NAME="boot_diskX%n"
BUS="scsi", SYSFS{vendor}="IBM-ESXS", SYSFS{model}="ST336605LW    !#", NAME="boot_disk%n"
EOF
	},
	{
		desc		=> "label test of max sysfs files",
		subsys		=> "block",
		devpath		=> "block/sda/sda1",
		exp_name	=> "boot_disk1" ,
		conf		=> <<EOF
BUS="scsi", SYSFS{vendor}="IBM-ESXS", SYSFS{model}="ST336605LW    !#", SYSFS{scsi_level}="4", SYSFS{rev}="B245", SYSFS{type}="2", SYSFS{queue_depth}="32", NAME="boot_diskXX%n"
BUS="scsi", SYSFS{vendor}="IBM-ESXS", SYSFS{model}="ST336605LW    !#", SYSFS{scsi_level}="4", SYSFS{rev}="B245", SYSFS{type}="0", NAME="boot_disk%n"
EOF
	},
	{
		desc		=> "catch device by *",
		subsys		=> "tty",
		devpath		=> "class/tty/ttyUSB0",
		exp_name	=> "visor/0" ,
		conf		=> <<EOF
KERNEL="ttyUSB*", NAME="visor/%n"
EOF
	},
	{
		desc		=> "catch device by * - take 2",
		subsys		=> "tty",
		devpath		=> "class/tty/ttyUSB0",
		exp_name	=> "visor/0" ,
		conf		=> <<EOF
KERNEL="*USB1", NAME="bad"
KERNEL="*USB0", NAME="visor/%n"
EOF
	},
	{
		desc		=> "catch device by ?",
		subsys		=> "tty",
		devpath		=> "class/tty/ttyUSB0",
		exp_name	=> "visor/0" ,
		conf		=> <<EOF
KERNEL="ttyUSB??*", NAME="visor/%n-1"
KERNEL="ttyUSB??", NAME="visor/%n-2"
KERNEL="ttyUSB?", NAME="visor/%n"
EOF
	},
	{
		desc		=> "catch device by character class",
		subsys		=> "tty",
		devpath		=> "class/tty/ttyUSB0",
		exp_name	=> "visor/0" ,
		conf		=> <<EOF
KERNEL="ttyUSB[A-Z]*", NAME="visor/%n-1"
KERNEL="ttyUSB?[0-9]", NAME="visor/%n-2"
KERNEL="ttyUSB[0-9]*", NAME="visor/%n"
EOF
	},
	{
		desc		=> "replace kernel name",
		subsys		=> "tty",
		devpath		=> "class/tty/ttyUSB0",
		exp_name	=> "visor" ,
		conf		=> <<EOF
KERNEL="ttyUSB0", NAME="visor"
EOF
	},
	{
		desc		=> "Handle comment lines in config file (and replace kernel name)",
		subsys		=> "tty",
		devpath		=> "class/tty/ttyUSB0",
		exp_name	=> "visor" ,
		conf		=> <<EOF
# this is a comment
KERNEL="ttyUSB0", NAME="visor"

EOF
	},
	{
		desc		=> "Handle comment lines in config file with whitespace (and replace kernel name)",
		subsys		=> "tty",
		devpath		=> "class/tty/ttyUSB0",
		exp_name	=> "visor" ,
		conf		=> <<EOF
 # this is a comment with whitespace before the comment 
KERNEL="ttyUSB0", NAME="visor"

EOF
	},
	{
		desc		=> "Handle empty lines in config file (and replace kernel name)",
		subsys		=> "tty",
		devpath		=> "class/tty/ttyUSB0",
		exp_name	=> "visor" ,
		conf		=> <<EOF

KERNEL="ttyUSB0", NAME="visor"

EOF
	},
	{
		desc		=> "subdirectory handling",
		subsys		=> "tty",
		devpath		=> "class/tty/ttyUSB0",
		exp_name	=> "sub/direct/ory/visor" ,
		conf		=> <<EOF
KERNEL="ttyUSB0", NAME="sub/direct/ory/visor"
EOF
	},
	{
		desc		=> "place on bus of scsi partition",
		subsys		=> "block",
		devpath		=> "block/sda/sda3",
		exp_name	=> "first_disk3" ,
		conf		=> <<EOF
BUS="scsi", PLACE="0:0:0:0", NAME="first_disk%n"
EOF
	},
	{
		desc		=> "test NAME substitution chars",
		subsys		=> "block",
		devpath		=> "block/sda/sda3",
		exp_name	=> "Major:8:minor:3:kernelnumber:3:bus:0:0:0:0" ,
		conf		=> <<EOF
BUS="scsi", PLACE="0:0:0:0", NAME="Major:%M:minor:%m:kernelnumber:%n:bus:%b"
EOF
	},
	{
		desc		=> "test NAME substitution chars (with length limit)",
		subsys		=> "block",
		devpath		=> "block/sda/sda3",
		exp_name	=> "M8-m3-n3-b0:0-sIBM" ,
		conf		=> <<EOF
BUS="scsi", PLACE="0:0:0:0", NAME="M%M-m%m-n%n-b%3b-s%3s{vendor}"
EOF
	},
	{
		desc		=> "old style SYSFS_ attribute",
		subsys		=> "block",
		devpath		=> "block/sda",
		exp_name	=> "good" ,
		conf		=> <<EOF
BUS="scsi", SYSFS_vendor="IBM-ESXS", NAME="good"
EOF
	},
	{
		desc		=> "sustitution of sysfs value (%s{file})",
		subsys		=> "block",
		devpath		=> "block/sda",
		exp_name	=> "disk-IBM-ESXS-sda" ,
		conf		=> <<EOF
BUS="scsi", SYSFS{vendor}="IBM-ESXS", NAME="disk-%s{vendor}-%k"
KERNEL="ttyUSB0", NAME="visor"
EOF
	},
	{
		desc		=> "program result substitution",
		subsys		=> "block",
		devpath		=> "block/sda/sda3",
		exp_name	=> "special-device-3" ,
		conf		=> <<EOF
BUS="scsi", PROGRAM="/bin/echo -n special-device", RESULT="-special-*", NAME="%c-1-%n"
BUS="scsi", PROGRAM="/bin/echo -n special-device", RESULT="special--*", NAME="%c-2-%n"
BUS="scsi", PROGRAM="/bin/echo -n special-device", RESULT="special-device-", NAME="%c-3-%n"
BUS="scsi", PROGRAM="/bin/echo -n special-device", RESULT="special-devic", NAME="%c-4-%n"
BUS="scsi", PROGRAM="/bin/echo -n special-device", RESULT="special-*", NAME="%c-%n"
EOF
	},
	{
		desc		=> "program result substitution",
		subsys		=> "block",
		devpath		=> "block/sda/sda3",
		exp_name	=> "test-0:0:0:0" ,
		conf		=> <<EOF
BUS="scsi", PROGRAM="/bin/echo -n test-%b", RESULT="test-0:0*", NAME="%c"
EOF
	},
	{
		desc		=> "program with escaped format char (tricky: callout returns format char!)",
		subsys		=> "block",
		devpath		=> "block/sda/sda3",
		exp_name	=> "escape-3" ,
		conf		=> <<EOF
BUS="scsi", PROGRAM="/bin/echo -n escape-%%n", KERNEL="sda3", NAME="%c"
EOF
	},
	{
		desc		=> "program with lots of arguments",
		subsys		=> "block",
		devpath		=> "block/sda/sda3",
		exp_name	=> "foo9" ,
		conf		=> <<EOF
BUS="scsi", PROGRAM="/bin/echo -n foo3 foo4 foo5 foo6 foo7 foo8 foo9", KERNEL="sda3", NAME="%c{7}"
EOF
	},
	{
		desc		=> "program with subshell",
		subsys		=> "block",
		devpath		=> "block/sda/sda3",
		exp_name	=> "bar9" ,
		conf		=> <<EOF
BUS="scsi", PROGRAM="/bin/sh -c 'echo foo3 foo4 foo5 foo6 foo7 foo8 foo9 | sed  s/foo9/bar9/'", KERNEL="sda3", NAME="%c{7}"
EOF
	},
	{
		desc		=> "program arguments combined with apostrophes",
		subsys		=> "block",
		devpath		=> "block/sda/sda3",
		exp_name	=> "foo7" ,
		conf		=> <<EOF
BUS="scsi", PROGRAM="/bin/echo -n 'foo3 foo4'   'foo5   foo6   foo7 foo8'", KERNEL="sda3", NAME="%c{5}"
EOF
	},
	{
		desc		=> "characters before the %c{N} substitution",
		subsys		=> "block",
		devpath		=> "block/sda/sda3",
		exp_name	=> "my-foo9" ,
		conf		=> <<EOF
BUS="scsi", PROGRAM="/bin/echo -n foo3 foo4 foo5 foo6 foo7 foo8 foo9", KERNEL="sda3", NAME="my-%c{7}"
EOF
	},
	{
		desc		=> "substitute the second to last argument",
		subsys		=> "block",
		devpath		=> "block/sda/sda3",
		exp_name	=> "my-foo8" ,
		conf		=> <<EOF
BUS="scsi", PROGRAM="/bin/echo -n foo3 foo4 foo5 foo6 foo7 foo8 foo9", KERNEL="sda3", NAME="my-%c{6}"
EOF
	},
	{
		desc		=> "program result substitution (numbered part of)",
		subsys		=> "block",
		devpath		=> "block/sda/sda3",
		exp_name	=> "link1" ,
		conf		=> <<EOF
BUS="scsi", PROGRAM="/bin/echo -n node link1 link2", RESULT="node *", NAME="%c{1}", SYMLINK="%c{2} %c{3}"
EOF
	},
	{
		desc		=> "program result substitution (numbered part of+)",
		subsys		=> "block",
		devpath		=> "block/sda/sda3",
		exp_name	=> "link3" ,
		conf		=> <<EOF
BUS="scsi", PROGRAM="/bin/echo -n node link1 link2 link3 link4", RESULT="node *", NAME="%c{1}", SYMLINK="%c{2+}"
EOF
	},
	{
		desc		=> "invalid program for device with no bus",
		subsys		=> "tty",
		devpath		=> "class/tty/console",
		exp_name	=> "TTY" ,
		conf		=> <<EOF
BUS="scsi", PROGRAM="/bin/echo -n foo", RESULT="foo", NAME="foo"
KERNEL="console", NAME="TTY"
EOF
	},
	{
		desc		=> "valid program for device with no bus",
		subsys		=> "tty",
		devpath		=> "class/tty/console",
		exp_name	=> "foo" ,
		conf		=> <<EOF
PROGRAM="/bin/echo -n foo", RESULT="foo", NAME="foo"
KERNEL="console", NAME="TTY"
EOF
	},
	{
		desc		=> "invalid label for device with no bus",
		subsys		=> "tty",
		devpath		=> "class/tty/console",
		exp_name	=> "TTY" ,
		conf		=> <<EOF
BUS="foo", SYSFS{dev}="5:1", NAME="foo"
KERNEL="console", NAME="TTY"
EOF
	},
	{
		desc		=> "valid label for device with no bus",
		subsys		=> "tty",
		devpath		=> "class/tty/console",
		exp_name	=> "foo" ,
		conf		=> <<EOF
SYSFS{dev}="5:1", NAME="foo"
KERNEL="console", NAME="TTY"
EOF
	},
	{
		desc		=> "program and bus type match",
		subsys		=> "block",
		devpath		=> "block/sda",
		exp_name	=> "scsi-0:0:0:0" ,
		conf		=> <<EOF
BUS="usb", PROGRAM="/bin/echo -n usb-%b", NAME="%c"
BUS="scsi", PROGRAM="/bin/echo -n scsi-%b", NAME="%c"
BUS="foo", PROGRAM="/bin/echo -n foo-%b", NAME="%c"
EOF
	},
	{
		desc		=> "symlink creation (same directory)",
		subsys		=> "tty",
		devpath		=> "class/tty/ttyUSB0",
		exp_name	=> "visor0" ,
		conf		=> <<EOF
KERNEL="ttyUSB[0-9]*", NAME="ttyUSB%n", SYMLINK="visor%n"
EOF
	},
	{
		desc		=> "symlink creation (relative link back)",
		subsys		=> "block",
		devpath		=> "block/sda/sda2",
		exp_name	=> "1/2/a/b/symlink" ,
		conf		=> <<EOF
BUS="scsi", SYSFS{vendor}="IBM-ESXS", NAME="1/2/node", SYMLINK="1/2/a/b/symlink"
EOF
	},
	{
		desc		=> "symlink creation (relative link forward)",
		subsys		=> "block",
		devpath		=> "block/sda/sda2",
		exp_name	=> "1/2/symlink" ,
		conf		=> <<EOF
BUS="scsi", SYSFS{vendor}="IBM-ESXS", NAME="1/2/a/b/node", SYMLINK="1/2/symlink"
EOF
	},
	{
		desc		=> "symlink creation (relative link back and forward)",
		subsys		=> "block",
		devpath		=> "block/sda/sda2",
		exp_name	=> "1/2/c/d/symlink" ,
		conf		=> <<EOF
BUS="scsi", SYSFS{vendor}="IBM-ESXS", NAME="1/2/a/b/node", SYMLINK="1/2/c/d/symlink"
EOF
	},
	{
		desc		=> "multiple symlinks",
		subsys		=> "tty",
		devpath		=> "class/tty/ttyUSB0",
		exp_name	=> "second-0" ,
		conf		=> <<EOF
KERNEL="ttyUSB0", NAME="visor", SYMLINK="first-%n second-%n third-%n"
EOF
	},
	{
		desc		=> "create all possible partitions",
		subsys		=> "block",
		devpath		=> "block/sda",
		exp_name	=> "boot_disk15" ,
		conf		=> <<EOF
BUS="scsi", SYSFS{vendor}="IBM-ESXS", NAME{all_partitions}="boot_disk"
EOF
	},
	{
		desc		=> "sysfs parent hierarchy",
		subsys		=> "tty",
		devpath		=> "class/tty/ttyUSB0",
		exp_name	=> "visor" ,
		conf		=> <<EOF
SYSFS{idProduct}="2008", NAME="visor"
EOF
	},
	{
		desc		=> "name test with ! in the name",
		subsys		=> "block",
		devpath		=> "block/rd!c0d0",
		exp_name	=> "rd/c0d0" ,
		conf		=> <<EOF
BUS="scsi", NAME="%k"
KERNEL="ttyUSB0", NAME="visor"
EOF
	},
	{
		desc		=> "name test with ! in the name, but no matching rule",
		subsys		=> "block",
		devpath		=> "block/rd!c0d0",
		exp_name	=> "rd/c0d0" ,
		conf		=> <<EOF
KERNEL="ttyUSB0", NAME="visor"
EOF
	},
	{
		desc		=> "ID rule",
		subsys		=> "block",
		devpath		=> "block/sda",
		exp_name	=> "scsi-0:0:0:0",
		conf		=> <<EOF
BUS="usb", ID="0:0:0:0", NAME="not-scsi"
BUS="scsi", ID="0:0:0:1", NAME="no-match"
BUS="scsi", ID=":0", NAME="short-id"
BUS="scsi", ID="/0:0:0:0", NAME="no-match"
BUS="scsi", ID="0:0:0:0", NAME="scsi-0:0:0:0"
EOF
	},
	{
		desc		=> "ID wildcard all",
		subsys		=> "block",
		devpath		=> "block/sda",
		exp_name	=> "scsi-0:0:0:0",
		conf		=> <<EOF
BUS="scsi", ID="*:1", NAME="no-match"
BUS="scsi", ID="*:0:1", NAME="no-match"
BUS="scsi", ID="*:0:0:1", NAME="no-match"
BUS="scsi", ID="*", NAME="scsi-0:0:0:0"
BUS="scsi", ID="0:0:0:0", NAME="bad"
EOF
	},
	{
		desc		=> "ID wildcard partial",
		subsys		=> "block",
		devpath		=> "block/sda",
		exp_name	=> "scsi-0:0:0:0",
		conf		=> <<EOF
BUS="scsi", ID="*:0", NAME="scsi-0:0:0:0"
BUS="scsi", ID="0:0:0:0", NAME="bad"
EOF
	},
	{
		desc		=> "ID wildcard partial 2",
		subsys		=> "block",
		devpath		=> "block/sda",
		exp_name	=> "scsi-0:0:0:0",
		conf		=> <<EOF
BUS="scsi", ID="*:0:0:0", NAME="scsi-0:0:0:0"
BUS="scsi", ID="0:0:0:0", NAME="bad"
EOF
	},
	{
		desc		=> "ignore SYSFS attribute whitespace",
		subsys		=> "block",
		devpath		=> "block/sda",
		exp_name	=> "ignored",
		conf		=> <<EOF
BUS="scsi", SYSFS{whitespace_test}="WHITE  SPACE", NAME="ignored"
EOF
	},
	{
		desc		=> "do not ignore SYSFS attribute whitespace",
		subsys		=> "block",
		devpath		=> "block/sda",
		exp_name	=> "matched-with-space",
		conf		=> <<EOF
BUS="scsi", SYSFS{whitespace_test}="WHITE  SPACE ", NAME="wrong-to-ignore"
BUS="scsi", SYSFS{whitespace_test}="WHITE  SPACE   ", NAME="matched-with-space"
EOF
	},
	{
		desc		=> "SYMLINK only rule",
		subsys		=> "block",
		devpath		=> "block/sda",
		exp_name	=> "symlink-only2",
		conf		=> <<EOF
BUS="scsi", KERNEL="sda", SYMLINK="symlink-only1"
BUS="scsi", KERNEL="sda", SYMLINK="symlink-only2"
BUS="scsi", KERNEL="sda", NAME="link", SYMLINK="symlink0"
EOF
	},
	{
		desc		=> "permissions test",
		subsys		=> "block",
		devpath		=> "block/sda",
		exp_name	=> "node",
		perms		=> "5000::0444",
		conf		=> <<EOF
BUS="scsi", KERNEL="sda", NAME="node", OWNER="5000", MODE="0444"
EOF
	},
	{
		desc		=> "major/minor number test",
		subsys		=> "block",
		devpath		=> "block/sda",
		exp_name	=> "node",
		exp_majorminor	=> "8:0",
		conf		=> <<EOF
BUS="scsi", KERNEL="sda", NAME="node"
EOF
	},
	{
		desc		=> "big minor number test",
		subsys		=> "i2c-dev",
		devpath		=> "class/i2c-dev/i2c-300",
		exp_name	=> "node",
		exp_majorminor	=> "89:300",
		conf		=> <<EOF
KERNEL="i2c-300", NAME="node"
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

my $error = 0;

sub run_test {
	my ($config, $number) = @_;

	print "TEST $number: $config->{desc}\n";
	print "device \'$config->{devpath}\' expecting node \'$config->{exp_name}\'\n";

	udev("add", $config->{subsys}, $config->{devpath}, \$config->{conf});
	if (-e "$PWD/$udev_root$config->{exp_name}") {

		my ($dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size,
		    $atime, $mtime, $ctime, $blksize, $blocks) = stat("$PWD/$udev_root$config->{exp_name}");

		if (defined($config->{perms})) {
			my $wrong = 0;
			$config->{perms} =~ m/^(.*):(.*):(.*)$/;
			if ($1 ne "") {
				if ($uid != $1) { $wrong = 1; };
			}
			if ($2 ne "") {
				if ($gid != $2) { $wrong = 1; };
			}
			if ($3 ne "") {
				if (($mode & 07777) != oct($3)) { $wrong = 1; };
			}
			if ($wrong == 0) {
				print "permissions: ok    ";
			} else {
				printf "expected permissions are: %i:%i:%#o\n", $1, $2, oct($3);
				printf "created permissions are : %i:%i:%#o\n", $uid, $gid, $mode & 07777;
				$error++;
			}
		}

		if (defined($config->{exp_majorminor})) {
			my $major = ($rdev >> 8) & 0xfff;
			my $minor = ($rdev & 0xff) | (($rdev >> 12) & 0xfff00);

			my $wrong = 0;
			$config->{exp_majorminor} =~ m/^(.*):(.*)$/;
			if ($1 ne "") {
				if ($major != $1) { $wrong = 1; };
			}
			if ($2 ne "") {
				if ($minor != $2) { $wrong = 1; };
			}
			if ($wrong == 0) {
				print "major:minor: ok    ";
			} else {
				printf "expected major:minor is: %i:%i\n", $1, $2;
				printf "created major:minor is : %i:%i\n", $major, $minor;
				$error++;
			}
		}

		print "add: ok    ";
	} else {
		print "add: error\n";
		system("tree $udev_root");
		print "\n";
		$error++;
	}

	udev("remove", $config->{subsys}, $config->{devpath}, \$config->{conf});
	if ((-e "$PWD/$udev_root$config->{exp_name}") ||
	    (-l "$PWD/$udev_root$config->{exp_name}")) {
		print "remove: error\n\n";
		system("tree $udev_root");
		$error++;
	} else {
		print "remove: ok\n\n";
	}
}

# prepare
system("rm -rf $udev_root");
mkdir($udev_root) || die "unable to create udev_root: $udev_root\n";

# create initial config file
open CONF, ">$main_conf" || die "unable to create config file: $main_conf";
print CONF "udev_root=\"$udev_root\"\n";
print CONF "udev_db=\"$udev_db\"\n";
print CONF "udev_rules=\"$conf_tmp\"\n";
print CONF "udev_permissions=\"$perm\"\n";
close CONF;

my $test_num = 1;

if ($ARGV[0]) {
	# only run one test
	$test_num = $ARGV[0];
	print "udev-test will run test number $test_num only\n";

	run_test($tests[$test_num-1], $test_num);
} else {
	# test all
	print "\nudev-test will run ".($#tests + 1)." tests:\n\n";

	foreach my $config (@tests) {
		run_test($config, $test_num);
		$test_num++;

	}
}

print "$error errors occured\n\n";

# cleanup
unlink($udev_db);
system("rm -rf $udev_root");
unlink($conf_tmp);
unlink($main_conf);

