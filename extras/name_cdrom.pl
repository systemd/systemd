#!/usr/bin/perl

# a horribly funny script that shows how flexible udev can really be
# This is to be executed by udev with the following rules:
# KERNEL="[hs]d[a-z]", PROGRAM="name_cdrom.pl %M %m", NAME="%1c", SYMLINK="cdrom"

use strict;
use warnings;

use CDDB_get qw( get_cddb );

my $dev_node = "/tmp/cd_foo";

# following variables just need to be declared if different from defaults
my %config;
$config{CDDB_HOST}="freedb.freedb.org";		# set cddb host
$config{CDDB_PORT}=8880;			# set cddb port
$config{CDDB_MODE}="cddb";			# set cddb mode: cddb or http
$config{CD_DEVICE}="$dev_node";			# set cd device

# No user interaction, this is a automated script!
$config{input}=0;

my $major = $ARGV[0];
my $minor = $ARGV[1];

# create our temp device node to read the cd info from
unlink($dev_node);
if (system("mknod $dev_node b $major $minor")) {
       die "bad mknod failed";
}

# get it on
my %cd=get_cddb(\%config);

# remove the dev node we just created
unlink($dev_node);

# print out our cd name if we have found it or skip rule by nonzero exit
if (defined $cd{title}) {
	$cd{artist} =~ s/ /_/g;
	$cd{title} =~ s/ /_/g;
	print "$cd{artist}-$cd{title}\n";
} else {
	exit -1;
}
