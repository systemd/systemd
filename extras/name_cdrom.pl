#!/usr/bin/perl

# a horribly funny script that shows how flexible udev can really be
# This is to be executed by udev with the following rules:
# CALLOUT, BUS="ide", PROGRAM="name_cdrom.pl %M %m", ID="good*", NAME="%1c", SYMLINK="cdrom" 
# CALLOUT, BUS="scsi", PROGRAM="name_cdrom.pl %M %m", ID="good*", NAME="%1c", SYMLINK="cdrom" 
#
# The scsi rule catches USB cdroms and ide-scsi devices.
#

use CDDB_get qw( get_cddb );

my %config;

$dev_node = "/tmp/cd_foo";

# following variables just need to be declared if different from defaults
$config{CDDB_HOST}="freedb.freedb.org";		# set cddb host
$config{CDDB_PORT}=8880;			# set cddb port
$config{CDDB_MODE}="cddb";			# set cddb mode: cddb or http
$config{CD_DEVICE}="$dev_node";			# set cd device

# No user interaction, this is a automated script!
$config{input}=0;

$major = $ARGV[0];
$minor = $ARGV[1];

# create our temp device node to read the cd info from
if (system("mknod $dev_node b $major $minor")) {
       die "bad mknod failed";
       }

# get it on
my %cd=get_cddb(\%config);

# remove the dev node we just created
unlink($dev_node);

# print out our cd name if we have found it
unless(defined $cd{title}) {
	print"bad unknown cdrom\n";
} else {
	print "good $cd{artist}_$cd{title}\n";
}
