#!/usr/bin/perl -w
#
# udev-log-script
#
# Copyright (C) Intel Corp, 2004
#
# Author: Yin Hu <hu.yin@intel.com> 
#
# This is a script for replacing udev binary during udevsend/udevd testing.
# It just simply logs the event information sent by udved in order to
# test script udevd-test.pl can analyze whether udved execute as we expected.
# You should not execute this script directly because it will be invoked by
# udevd automatically.
#
# Before you run your test please modify $log_file to designate where the udev
# log file should be placed, in fact, the default value is ok.
#
# 
#	This program is free software; you can redistribute it and/or modify it
# 	under the terms of the GNU General Public License as published by the
# 	Free Software Foundation version 2 of the License.
#  
# 	This program is distributed in the hope that it will be useful, but
# 	WITHOUT ANY WARRANTY; without even the implied warranty of
# 	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# 	General Public License for more details.
#
#	You should have received a copy of the GNU General Public License along
# 	with this program; if not, write to the Free Software Foundation, Inc.,
# 	675 Mass Ave, Cambridge, MA 02139, USA.
#

use warnings;
use strict;

# modifiable settings
my $log_file  = "/tmp/udev_log.txt";

if ($ARGV[0]) {
	my $subsystem = $ARGV[0];
	my $devpath = $ENV{DEVPATH};
	my $action = $ENV{ACTION};
	my $time = time();

	# Logging
        if (open(LOGF, ">>$log_file")) {
		print LOGF "$devpath,$action,$subsystem,$time\n";
	} else {
		print "File open failed. \n";
		exit 1;
	}
        close(LOGF);

	exit 0;
} else {
	print "Too less argument count.\n";
	exit 1;
}
