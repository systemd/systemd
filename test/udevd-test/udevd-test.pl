#!/usr/bin/perl -w
#
# udevd-test
#
# Copyright (C) Intel Corp, 2004
#
# Author: Yin Hu <hu.yin@intel.com> 
#
# Provides automated testing of the udevd binary.This test script is self-contained.
# Before you run this script please modify $sysfs to locate your sysfs filesystem, 
# modify $udevsend_bin to locate your udevsend binary,
# modify $udev_bin to locate dummy udev script,
# modify $udev_bin2 to locate another dummy udev script ( amplify the execution time for test),
# modify $log_file to locate where udev script have placed the log file,
# modify $time_out to decide the time out for events,
# modify $udev_exe_time to decide the execution time for dummy udev script.
#
# Detail information of each test case please refer to the header of corresponding
# test case function.
#
#
#	This program is free software; you can redistribute it and/or modify it
#	under the terms of the GNU General Public License as published by the
#	Free Software Foundation version 2 of the License.
#
#	This program is distributed in the hope that it will be useful, but
#	WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#	General Public License for more details.
#
#	You should have received a copy of the GNU General Public License along
#	with this program; if not, write to the Free Software Foundation, Inc.,
#	675 Mass Ave, Cambridge, MA 02139, USA.
#

use warnings;
use strict;

# modifiable settings
my $sysfs     =		"../sys";
my $udevd_bin =	"../../udevd";
my $udevsend_bin =	"../../udevsend";
my $udev_bin  =		"$ENV{'PWD'}/udev-log-script.pl";
my $udev_bin2 =		"$ENV{'PWD'}/udev-log-amplify.pl";
my $log_file  =		"/tmp/udev_log.txt";
my $time_out  =		10;
my $udev_exe_time =	5;

# global variables
my $test_case = 0;

# common functions

sub restart_daemon {
	my ($udev_binary) = @_;

	system("killall udevd");
	system("rm -f $log_file");
	sleep 1;

	if (!defined($udev_binary)) {
		$udev_binary = $udev_bin;
	}

	$ENV{'UDEV_BIN'} = $udev_binary;
	system("/bin/sh -c $udevd_bin&");
	sleep(1);
}

sub udevsend {
	# This function prepares corresponding environment variables
	# and then call $udevsend_bin to send event.

	my ($seqnum, $devpath, $action, $subsystem, $script) = @_;

	%ENV = ();
	$ENV{'DEVPATH'} = $devpath;
	$ENV{'ACTION'} = $action;
	$ENV{'SUBSYSTEM'} = $subsystem;

	if ( $seqnum != -1) {
		$ENV{SEQNUM} = $seqnum;
	}

	return system("$udevsend_bin $subsystem");
}

sub check_count_and_time { 
	my $event_recv_time;
	my $udev_fork_time;
	my $log_ln_count = 0;
	my $line;
	my @content;
	my @line_items;
	my $diff;

	($event_recv_time) = @_;

	print "   event receiving time:  $event_recv_time\n\n";

	open(LOGF, $log_file) || die "Opening file $log_file: $!";
	@content = <LOGF>;
	foreach $line ( @content ) {
		@line_items = split(/,/,$line);
		print "   device: $line_items[0], action: $line_items[1] \n";
		print "   forking udev time:     $line_items[-1]";
		$diff = $line_items[-1] - $event_recv_time;
		print "   the delay time is:     $diff s \n\n";
		if ( $diff > $time_out+10 ) {
			print "   the delay time is: $diff \n";
			print "   udevd doesn't act properly. \n";
			exit 1;
		}
		$log_ln_count++;
	}
	close(LOGF);

	return $log_ln_count;
}

sub check_sysfs_device_exist {
	# check if the designated devices exist
	my @dev_list = @_;
	my $dev;

	foreach $dev (@dev_list) {
		if (! -e $dev) {
			print "the designated device $dev doesn't exist. please change a device!\n";
			exit 1;
		}
	}
}

sub show_result {
	my $event_recv_time;
	my $udev_fork_time;
	my $line;
	my @content;
	my @line_items;
	my $diff;

	($event_recv_time) = @_;

	print "   event receiving time:  $event_recv_time\n\n";

	open(LOGF, $log_file) || die "Opening file $log_file: $!";
	@content = <LOGF>;
	foreach $line ( @content ) {
		@line_items = split(/,/,$line);
		print "   device: $line_items[0], action: $line_items[1] \n";
		print "   forking udev time:     $line_items[-1]";
		$diff = $line_items[-1] - $event_recv_time;
		print "   the delay time is:     $diff s \n\n";
	}
	close(LOGF);
}

sub show_result_tm_out {
	my $event_recv_time;
	my $udev_fork_time;
	my $line;
	my @content;
	my @line_items;
	my $diff;

	($event_recv_time) = @_;

	print "   event receiving time:  $event_recv_time\n\n";

	open(LOGF, $log_file) || die "Opening file $log_file: $!";
	@content = <LOGF>;
	foreach $line ( @content ) {
		@line_items = split(/,/,$line);
		print "   device: $line_items[0], action: $line_items[1] \n";
		print "   forking udev time:     $line_items[-1]";
		$diff = $line_items[-1] - $event_recv_time;
		print "   the delay time is:     $diff s \n\n";
		if ( $diff < $time_out ) {
			print "   the delay time is:     $diff \n";
			print "   udevd doesn't act properly. \n";
			exit 1;
		}
	}
	close(LOGF);
}

sub show_result_immediate {
	my $event_recv_time;
	my $udev_fork_time;
	my $line;
	my @content;
	my @line_items;
	my $diff;

	($event_recv_time) = @_;

	print "   event receiving time:  $event_recv_time\n\n";

	open(LOGF, $log_file) || die "Opening file $log_file: $!";
	@content = <LOGF>;
	foreach $line ( @content ) {
		@line_items = split(/,/,$line);
		print "   device: $line_items[0], action: $line_items[1] \n";
		print "   forking udev time:     $line_items[-1]";
		$diff = $line_items[-1] - $event_recv_time;
		print "   the delay time is:     $diff s \n\n";
		if ( $diff > $time_out ) {
			print "   the delay time is:     $diff \n";
			print "   udevd doesn't act properly. \n";
			exit 1;
		}
	}
	close(LOGF);
}

sub check_exe_time {
	my @exe_time;
	my $i = 0;
	my $line;
	my @content;
	my @line_items;
	my $diff;

	open(LOGF, $log_file) || die "Opening file $log_file: $!";
	@content = <LOGF>;
	close(LOGF);
	foreach $line ( @content ) {
		@line_items = split(/,/,$line);
		$exe_time[$i] = $line_items[-1];
		$i++;
	}
	$diff = $exe_time[1] - $exe_time[0];
	if ( $diff < $udev_exe_time ) {
		print "   there are more than one udev instance for a single device at the same time. \n";
		exit 1;
	} else {
		print "   there is just one udev instance for a single device at the same time. \n";
	}
}

# test case functions
sub run_no_seq_test {
	print "Test case name:     no sequence number test\n";
	print "Test case purpose:  check whether udevd forks udev immediately when environment variable SEQNUM is null.\n";
	print "Test expected visible results: \n";
	print "   the delay time between event receiving and forking udev for udevd should be negligible, \n";
	print "   that is, udev should be forked at once. please notice the following time...\n\n";

	my $time;

	#
	# add devices event test
	#
	restart_daemon();

	# check if devices /block/sda exist
	check_sysfs_device_exist("$sysfs/block/sda");

	# log current system date/time
	$time = time();

	udevsend(-1, "/block/sda", "add", "block");

	# check if execution is successful in time
	sleep 1;
	show_result_immediate($time);
	print "   fork udev (add device) at once successfully.\n\n";

	#
	# remove devices event test
	#
	system("rm -f $log_file");

	# log current system date/time
	$time = time();

	udevsend(-1, "/block/sda", "remove", "block");

	# check if execution is successful in time
	sleep 1;
	show_result_immediate($time);
	print "   fork udev (remove device) at once successfully.\n\n";
	print "this case is ok\n\n";
}

sub run_normal_seq_test {
	print "Test case name:    normal sequence number stress test\n";
	print "Test case purpose: check whether udevd can fork massive udev instances for \n";
	print "                   massive sequential events successfully. \n";
	print "Test expected visible results: \n";
	print "   Populate all the devices in directory $sysfs/class/tty, fork udved to send add/remove \n";
	print "   event to udev for each device. \n";
	print "   We can see the delay time for each device should be negligible. \n\n";

	my @file_list;
	my $file;
	my $seq = 0;
	my $time;
	my $ret_seq;

	restart_daemon();
	@file_list = glob "$sysfs/class/tty/*";

	# log current system date/time for device add events
	$time = time();

	#
	# add devices event test
	#
	print "add device events test: \n";
	foreach $file (@file_list) {
		udevsend($seq, substr($file, length($sysfs), length($file)-length($sysfs)), "add", "tty");
		# check if execution is successful
		if ($? == 0) {
			$seq++;
		} else {
			print "add event: error\n\n";
			exit 1;
		}
	}

	# we'd better wait the udev to create all the device for a few seconds
	print "   wait for udevd processing about $time_out s... \n\n";
	sleep $time_out + 5;

	$ret_seq = check_count_and_time($time);
	if ( $ret_seq != $seq ) {
		print "   add event: failed. some device-adding events fail to execute.\n\n";
		exit 1;
	} else {
		print "   $seq pieces of device-adding events have executed successfully.\n\n";
	}

	# log current system date/time for device remove events
	$time = time();

	#
	# remove devices event test
	#
	print "remove device events test: \n";
	restart_daemon();
	@file_list = glob "$sysfs/class/tty/*"; 
	$seq = 0;
	foreach $file (@file_list) {
		udevsend($seq, substr($file, length($sysfs), length($file)-length($sysfs)), "remove", "tty");
		# check if execution is successful
		if ($? == 0) {
			$seq++;
		} else {
			print "remove event: error\n\n";
			exit 1;
		}
	}

	# we'd better wait the udev to create all the device for a few seconds
	print "   waiting for udev removing devices (about $time_out s)...\n";
	sleep $time_out + 5;

	# show results
	$ret_seq = check_count_and_time($time);
	if ( $ret_seq != $seq ) {
		print "   remove event: failed. some device-removing events fail to execute.\n\n";
		exit 1;
	} else {
		print "   $seq pieces of device-removing events have executed successfully.\n\n";
		print "this case is ok.\n\n";
	}
}

sub run_random_seq_test {
	print "Test case name:    random sequence number test case,\n";
	print "Test case purpose: check whether udevd can order the events with random sequence number \n";
	print "                   and fork udev correctly. \n";
	print "Test expected visible results: \n";
	print "   We have disordered the events sent to udevd, if udevd can order them correctly, the devices' \n";
	print "   add/remove sequence should be tty0, tty1, tty2. \n\n";

	my $time;

	# check if devices /class/tty/tty0, tty1, tty2 exist
	check_sysfs_device_exist("$sysfs/class/tty/tty0", "$sysfs/class/tty/tty1", "$sysfs/class/tty/tty2");

	#
	# add device events test
	#
	print "add device events test: \n";
	restart_daemon();

	# log current system date/time for device remove events
	$time = time();

	# parameters: 1 sequence number, 2 device, 3 action, 4 subsystem
	udevsend(3, "/class/tty/tty2", "add", "tty");
	udevsend(1, "/class/tty/tty0", "add", "tty");
	udevsend(2, "/class/tty/tty1", "add", "tty");
	print "   wait for udevd processing about $time_out s... \n\n";
	sleep $time_out+1;
	show_result_tm_out($time);

	#
	# remove device events test
	#
	print "\nremove device events test: \n";
	restart_daemon();

	# log current system date/time for device remove events
	$time = time();

	udevsend(3, "/class/tty/tty2", "remove", "tty");
	udevsend(2, "/class/tty/tty1", "remove", "tty");
	udevsend(1, "/class/tty/tty0", "remove", "tty");

	# show results
	print "   wait for udevd processing about $time_out s... \n\n";
	sleep $time_out+1;
	show_result_tm_out($time);
	print "this case is ok.\n\n";
}

sub run_expected_seq_test { 
	print "Test case name:    expected sequence number test \n";
	print "Test case purpose: check whether udevd fork udev immediately when the incoming event\n";
	print "                   is exactly the expected event sequence number.\n";
	print "Test expected visible results:\n";
	print "   first, udevd disposes disorder events(sequence number is 3,1,2,5,4,6),\n";
	print "   thus after disposed the expected event number for udevd is 7, when incoming event is 7, udevd\n";
	print "   should fork udev immediately, the delay time should be negligible. \n";
	print "   where: event 7 is (add device /class/tty/tty2) \n\n";

	my $time;

	# check if devices /class/tty0, tty1, tty2 exist
	check_sysfs_device_exist("$sysfs/class/tty/tty0", "$sysfs/class/tty/tty1", "$sysfs/class/tty/tty2");

	restart_daemon();

	# parameters: 1 sequence number, 2 device, 3 action, 4 subsystem
	udevsend(3, "/class/tty/tty2", "add", "tty");
	udevsend(1, "/class/tty/tty0", "add", "tty");
	udevsend(2, "/class/tty/tty1", "add", "tty");
	udevsend(5, "/class/tty/tty1", "remove", "tty");
	udevsend(4, "/class/tty/tty0", "remove", "tty");
	udevsend(6, "/class/tty/tty2", "remove", "tty");

	print "   wait for udevd timing out for disorder events (about $time_out s) \n\n";
	sleep $udev_exe_time + $time_out+1;
	system("rm -f $log_file");

	# log current system date/time for device remove events
	$time = time();

	# show results
	udevsend(7, "/class/tty/tty2", "add", "tty");
	sleep 1;
	print "   event sequence number: 7 \n";
	show_result_immediate($time);

	print "this case is ok.\n\n";
}

sub run_single_instance_test { 
	print "Test case name:    single instance running for a single device test \n";
	print "Test case purpose: check whether udevd only fork one udev instance for a single\n";
	print "                   device at the same time. For each event a udev instance is \n";
	print "                   executed in the background. All further events for the same \n";
	print "                   device are delayed until the execution is finished. This way \n";
	print "                   there will never be more than one instance running for a single \n";
	print "                   device at the same time.\n";
	print "Test expected visible results:\n";
	print "   In this test we amplify the execution time of udev (about 5 seconds), first, \n";
	print "   we send a add event for device /block/sda, and then we send a remove event, so the \n";
	print "   execution of remove event should be delayed until add is finished. \n\n";

	my $time;

	restart_daemon($udev_bin2);

	# check if device exists
	check_sysfs_device_exist("$sysfs/block/sda");

	# log current system date/time
	$time = time();

	udevsend(-1, "/block/sda", "add", "block");
	udevsend(-1, "/block/sda", "remove", "block");

	# show results
	print "   wait for udevd processing about $udev_exe_time s... \n\n";
	sleep $udev_exe_time+1;
	show_result_immediate($time);
	check_exe_time();
	print "this case is ok\n\n";
}

sub run_same_events_test { 
	print "Test case name:    event sequence number overlap test \n";
	print "Test case purpose: check whether udevd doesn't fork udev untill time out\n";
	print "                   when encountering a event with sequence number same as the pevious event. \n";
	print "Test expected visible results:\n";
	print "   event ( remove device /block/sda ) should be no delay, \n";
	print "   event ( add device /class/tty/tty1 ) should be delayed for $time_out s than its previous \n";
	print "   event ( remove device /block/sda ) \n\n";

	my $time;

	restart_daemon();

	# check if device exist
	check_sysfs_device_exist("$sysfs/block/sda", "$sysfs/class/tty/tty1");

	udevsend(0, "/block/sda", "add", "block");

	# log current system date/time
	sleep 1;
	$time = time();
	system("rm -f $log_file");

	udevsend(1, "/block/sda", "remove", "block");
	udevsend(1, "/class/tty/tty1", "add", "tty");

	# show results
	print "   wait for udevd processing about $time_out s... \n\n";
	sleep $time_out+1;
	show_result($time);
	print "this case is ok\n\n";
}

sub run_missing_seq_test {
	print "Test case name:    missing sequence number test \n";
	print "Test case purpose: check whether udevd doesn't fork udev untill time out\n";
	print "                   when certain event sequence number is missing.\n";
	print "Test expected visible results:\n";
	print "   the delay time for event(add device /block/sda) should be about $time_out s.\n\n";

	my $time;

	restart_daemon();

	# check if device exist
	check_sysfs_device_exist("$sysfs/block/sda", "$sysfs/class/tty/tty1");

	udevsend(0, "/class/tty/tty1", "add", "tty");
	udevsend(1, "/class/tty/tty1", "remove", "tty");
	sleep 1;

	# log current system date/time
	$time = time();
	system("rm -f $log_file");

	udevsend(3, "/block/sda", "add", "block");

	# show results
	print "   wait for udevd processing about $time_out s... \n\n";
	sleep $time_out+1;
	show_result($time);
	print "this case is ok\n\n";
}

sub run_all_cases_test { 
	run_no_seq_test();
	run_normal_seq_test();
	run_random_seq_test();
	run_missing_seq_test();
	run_expected_seq_test();
	run_same_events_test();
	run_single_instance_test();
}

# main program
if ($ARGV[0]) {
	$test_case = $ARGV[0];

	if ($test_case == 1) {
		run_no_seq_test();
	} elsif ($test_case == 2) {
		run_normal_seq_test();
	} elsif ($test_case == 3) {
		run_random_seq_test();
	} elsif ($test_case == 4) {
		run_missing_seq_test();
	} elsif ($test_case == 5) {
		run_expected_seq_test();
	} elsif ($test_case == 6) {
		run_single_instance_test();
	} elsif ($test_case == 7) {
		run_same_events_test();
	} else {
		run_all_cases_test();
	}
} else {
	# echo usage
	print "command format: perl udevd-test.pl <case number>\n";
	print "   test case:\n";
	print "           1: no event sequence number\n";
	print "           2: sequential event sequence number\n";
	print "           3: random event sequence number\n";
	print "           4: missing event sequence number\n";
	print "           5: the incoming event sequence number is right the expected sequence number\n";
	print "           6: single udev instance on a single device at the same time\n";
	print "           7: test event sequence number overlap\n";
	print "           9: all the cases\n\n";
}
