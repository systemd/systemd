#!/usr/bin/perl

# Horrible but funny script that shows how flexible udev can really be
# This is to be executed by udev with the following rule:
#   KERNEL="hd*[!0-9]|sr*", PROGRAM="name_cdrom.pl $tempnode", SYMLINK+="%c"

use strict;
use warnings;

use CDDB_get qw(get_cddb);

# following variables just need to be declared if different from defaults
my %config;
$config{'CDDB_HOST'} = "freedb.freedb.org";	# set cddb host
$config{'CDDB_PORT'} = 8880;			# set cddb port
$config{'CDDB_MODE'} = "cddb";			# set cddb mode: cddb or http
$config{'CD_DEVICE'} = $ARGV[0];		# set cd device
$config{'input'} = 0; 				# no user interaction

my %cd = get_cddb(\%config);

if (!defined $cd{title}) {
	exit 1;
}

# print out our cd name
$cd{artist} =~ s/ /_/g;
$cd{title} =~ s/ /_/g;
print "$cd{artist}-$cd{title}\n";

exit 0;
