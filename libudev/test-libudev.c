/*
 * test-libudev
 *
 * Copyright (C) 2008 Kay Sievers <kay.sievers@vrfy.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/select.h>

#include "libudev.h"

static void log_fn(struct udev *udev,
		   int priority, const char *file, int line, const char *fn,
		   const char *format, va_list args)
{
	printf("test-libudev: %s %s:%d ", fn, file, line);
	vprintf(format, args);
}

static void print_device(struct udev_device *device)
{
	const char *str;
	dev_t devnum;
	int count;
	struct udev_list_entry *list_entry;

	printf("*** device: %p ***\n", device);
	str = udev_device_get_action(device);
	if (str != NULL)
		printf("action:    '%s'\n", str);

	str = udev_device_get_syspath(device);
	printf("syspath:   '%s'\n", str);

	str = udev_device_get_sysname(device);
	printf("sysname:   '%s'\n", str);

	str = udev_device_get_sysnum(device);
	if (str != NULL)
		printf("sysnum:    '%s'\n", str);

	str = udev_device_get_devpath(device);
	printf("devpath:   '%s'\n", str);

	str = udev_device_get_subsystem(device);
	if (str != NULL)
		printf("subsystem: '%s'\n", str);

	str = udev_device_get_devtype(device);
	if (str != NULL)
		printf("devtype:   '%s'\n", str);

	str = udev_device_get_driver(device);
	if (str != NULL)
		printf("driver:    '%s'\n", str);

	str = udev_device_get_devnode(device);
	if (str != NULL)
		printf("devname:   '%s'\n", str);

	devnum = udev_device_get_devnum(device);
	if (major(devnum) > 0)
		printf("devnum:    %u:%u\n", major(devnum), minor(devnum));

	count = 0;
	udev_list_entry_foreach(list_entry, udev_device_get_devlinks_list_entry(device)) {
		printf("link:      '%s'\n", udev_list_entry_get_name(list_entry));
		count++;
	}
	if (count > 0)
		printf("found %i links\n", count);

	count = 0;
	udev_list_entry_foreach(list_entry, udev_device_get_properties_list_entry(device)) {
		printf("property:  '%s=%s'\n",
		       udev_list_entry_get_name(list_entry),
		       udev_list_entry_get_value(list_entry));
		count++;
	}
	if (count > 0)
		printf("found %i properties\n", count);

	str = udev_device_get_property_value(device, "MAJOR");
	if (str != NULL)
		printf("MAJOR: '%s'\n", str);

	str = udev_device_get_sysattr_value(device, "dev");
	if (str != NULL)
		printf("attr{dev}: '%s'\n", str);

	printf("\n");
}

static int test_device(struct udev *udev, const char *syspath)
{
	struct udev_device *device;

	printf("looking at device: %s\n", syspath);
	device = udev_device_new_from_syspath(udev, syspath);
	if (device == NULL) {
		printf("no device found\n");
		return -1;
	}
	print_device(device);
	udev_device_unref(device);
	return 0;
}

static int test_device_parents(struct udev *udev, const char *syspath)
{
	struct udev_device *device;
	struct udev_device *device_parent;

	printf("looking at device: %s\n", syspath);
	device = udev_device_new_from_syspath(udev, syspath);
	if (device == NULL)
		return -1;

	printf("looking at parents\n");
	device_parent = device;
	do {
		print_device(device_parent);
		device_parent = udev_device_get_parent(device_parent);
	} while (device_parent != NULL);

	printf("looking at parents again\n");
	device_parent = device;
	do {
		print_device(device_parent);
		device_parent = udev_device_get_parent(device_parent);
	} while (device_parent != NULL);
	udev_device_unref(device);

	return 0;
}

static int test_device_devnum(struct udev *udev)
{
	dev_t devnum = makedev(1, 3);
	struct udev_device *device;

	printf("looking up device: %u:%u\n", major(devnum), minor(devnum));
	device = udev_device_new_from_devnum(udev, 'c', devnum);
	if (device == NULL)
		return -1;
	print_device(device);
	udev_device_unref(device);
	return 0;
}

static int test_device_subsys_name(struct udev *udev)
{
	struct udev_device *device;

	printf("looking up device: 'block':'sda'\n");
	device = udev_device_new_from_subsystem_sysname(udev, "block", "sda");
	if (device == NULL)
		return -1;
	print_device(device);
	udev_device_unref(device);

	printf("looking up device: 'subsystem':'pci'\n");
	device = udev_device_new_from_subsystem_sysname(udev, "subsystem", "pci");
	if (device == NULL)
		return -1;
	print_device(device);
	udev_device_unref(device);

	printf("looking up device: 'drivers':'scsi:sd'\n");
	device = udev_device_new_from_subsystem_sysname(udev, "drivers", "scsi:sd");
	if (device == NULL)
		return -1;
	print_device(device);
	udev_device_unref(device);

	printf("looking up device: 'module':'printk'\n");
	device = udev_device_new_from_subsystem_sysname(udev, "module", "printk");
	if (device == NULL)
		return -1;
	print_device(device);
	udev_device_unref(device);
	return 0;
}

static int test_enumerate_print_list(struct udev_enumerate *enumerate)
{
	struct udev_list_entry *list_entry;
	int count = 0;

	udev_list_entry_foreach(list_entry, udev_enumerate_get_list_entry(enumerate)) {
		struct udev_device *device;

		device = udev_device_new_from_syspath(udev_enumerate_get_udev(enumerate),
						      udev_list_entry_get_name(list_entry));
		if (device != NULL) {
			printf("device: '%s' (%s)\n",
			       udev_device_get_syspath(device),
			       udev_device_get_subsystem(device));
			udev_device_unref(device);
			count++;
		}
	}
	printf("found %i devices\n\n", count);
	return count;
}

static int test_monitor(struct udev *udev)
{
	struct udev_monitor *udev_monitor;
	fd_set readfds;
	int fd;

	udev_monitor = udev_monitor_new_from_netlink(udev, "udev");
	if (udev_monitor == NULL) {
		printf("no socket\n");
		return -1;
	}
	if (udev_monitor_filter_add_match_subsystem_devtype(udev_monitor, "block", NULL) < 0 ||
	    udev_monitor_filter_add_match_subsystem_devtype(udev_monitor, "tty", NULL) < 0 ||
	    udev_monitor_filter_add_match_subsystem_devtype(udev_monitor, "usb", "usb_device") < 0) {
		printf("filter failed\n");
		return -1;
	}
	if (udev_monitor_enable_receiving(udev_monitor) < 0) {
		printf("bind failed\n");
		return -1;
	}

	fd = udev_monitor_get_fd(udev_monitor);
	FD_ZERO(&readfds);

	for (;;) {
		struct udev_device *device;
		int fdcount;

		FD_SET(STDIN_FILENO, &readfds);
		FD_SET(fd, &readfds);

		printf("waiting for events from udev, press ENTER to exit\n");
		fdcount = select(fd+1, &readfds, NULL, NULL, NULL);
		printf("select fd count: %i\n", fdcount);

		if (FD_ISSET(fd, &readfds)) {
			device = udev_monitor_receive_device(udev_monitor);
			if (device == NULL) {
				printf("no device from socket\n");
				continue;
			}
			print_device(device);
			udev_device_unref(device);
		}

		if (FD_ISSET(STDIN_FILENO, &readfds)) {
			printf("exiting loop\n");
			break;
		}
	}

	udev_monitor_unref(udev_monitor);
	return 0;
}

static int test_queue(struct udev *udev)
{
	struct udev_queue *udev_queue;
	unsigned long long int seqnum;
	struct udev_list_entry *list_entry;

	udev_queue = udev_queue_new(udev);
	if (udev_queue == NULL)
		return -1;
	seqnum = udev_queue_get_kernel_seqnum(udev_queue);
	printf("seqnum kernel: %llu\n", seqnum);
	seqnum = udev_queue_get_udev_seqnum(udev_queue);
	printf("seqnum udev  : %llu\n", seqnum);

	if (udev_queue_get_queue_is_empty(udev_queue))
		printf("queue is empty\n");
	printf("get queue list\n");
	udev_list_entry_foreach(list_entry, udev_queue_get_queued_list_entry(udev_queue))
		printf("queued: '%s' [%s]\n", udev_list_entry_get_name(list_entry), udev_list_entry_get_value(list_entry));
	printf("\n");
	printf("get queue list again\n");
	udev_list_entry_foreach(list_entry, udev_queue_get_queued_list_entry(udev_queue))
		printf("queued: '%s' [%s]\n", udev_list_entry_get_name(list_entry), udev_list_entry_get_value(list_entry));
	printf("\n");
	printf("get failed list\n");
	udev_list_entry_foreach(list_entry, udev_queue_get_failed_list_entry(udev_queue))
		printf("failed: '%s'\n", udev_list_entry_get_name(list_entry));
	printf("\n");

	list_entry = udev_queue_get_queued_list_entry(udev_queue);
	if (list_entry != NULL) {
		printf("event [%llu] is queued\n", seqnum);
		seqnum = strtoull(udev_list_entry_get_value(list_entry), NULL, 10);
		if (udev_queue_get_seqnum_is_finished(udev_queue, seqnum))
			printf("event [%llu] is not finished\n", seqnum);
		else
			printf("event [%llu] is finished\n", seqnum);
	}
	printf("\n");
	udev_queue_unref(udev_queue);
	return 0;
}

static int test_enumerate(struct udev *udev, const char *subsystem)
{
	struct udev_enumerate *udev_enumerate;

	printf("enumerate '%s'\n", subsystem == NULL ? "<all>" : subsystem);
	udev_enumerate = udev_enumerate_new(udev);
	if (udev_enumerate == NULL)
		return -1;
	udev_enumerate_add_match_subsystem(udev_enumerate, subsystem);
	udev_enumerate_scan_devices(udev_enumerate);
	test_enumerate_print_list(udev_enumerate);
	udev_enumerate_unref(udev_enumerate);

	printf("enumerate 'net' + duplicated scan + null + zero\n");
	udev_enumerate = udev_enumerate_new(udev);
	if (udev_enumerate == NULL)
		return -1;
	udev_enumerate_add_match_subsystem(udev_enumerate, "net");
	udev_enumerate_scan_devices(udev_enumerate);
	udev_enumerate_scan_devices(udev_enumerate);
	udev_enumerate_add_syspath(udev_enumerate, "/sys/class/mem/zero");
	udev_enumerate_add_syspath(udev_enumerate, "/sys/class/mem/null");
	udev_enumerate_add_syspath(udev_enumerate, "/sys/class/mem/zero");
	udev_enumerate_add_syspath(udev_enumerate, "/sys/class/mem/null");
	udev_enumerate_add_syspath(udev_enumerate, "/sys/class/mem/zero");
	udev_enumerate_add_syspath(udev_enumerate, "/sys/class/mem/null");
	udev_enumerate_add_syspath(udev_enumerate, "/sys/class/mem/null");
	udev_enumerate_add_syspath(udev_enumerate, "/sys/class/mem/zero");
	udev_enumerate_add_syspath(udev_enumerate, "/sys/class/mem/zero");
	udev_enumerate_scan_devices(udev_enumerate);
	test_enumerate_print_list(udev_enumerate);
	udev_enumerate_unref(udev_enumerate);

	printf("enumerate 'block'\n");
	udev_enumerate = udev_enumerate_new(udev);
	if (udev_enumerate == NULL)
		return -1;
	udev_enumerate_add_match_subsystem(udev_enumerate,"block");
	udev_enumerate_scan_devices(udev_enumerate);
	test_enumerate_print_list(udev_enumerate);
	udev_enumerate_unref(udev_enumerate);

	printf("enumerate 'not block'\n");
	udev_enumerate = udev_enumerate_new(udev);
	if (udev_enumerate == NULL)
		return -1;
	udev_enumerate_add_nomatch_subsystem(udev_enumerate, "block");
	udev_enumerate_scan_devices(udev_enumerate);
	test_enumerate_print_list(udev_enumerate);
	udev_enumerate_unref(udev_enumerate);

	printf("enumerate 'pci, mem, vc'\n");
	udev_enumerate = udev_enumerate_new(udev);
	if (udev_enumerate == NULL)
		return -1;
	udev_enumerate_add_match_subsystem(udev_enumerate, "pci");
	udev_enumerate_add_match_subsystem(udev_enumerate, "mem");
	udev_enumerate_add_match_subsystem(udev_enumerate, "vc");
	udev_enumerate_scan_devices(udev_enumerate);
	test_enumerate_print_list(udev_enumerate);
	udev_enumerate_unref(udev_enumerate);

	printf("enumerate 'subsystem'\n");
	udev_enumerate = udev_enumerate_new(udev);
	if (udev_enumerate == NULL)
		return -1;
	udev_enumerate_scan_subsystems(udev_enumerate);
	test_enumerate_print_list(udev_enumerate);
	udev_enumerate_unref(udev_enumerate);

	printf("enumerate 'property IF_FS_*=filesystem'\n");
	udev_enumerate = udev_enumerate_new(udev);
	if (udev_enumerate == NULL)
		return -1;
	udev_enumerate_add_match_property(udev_enumerate, "ID_FS*", "filesystem");
	udev_enumerate_scan_devices(udev_enumerate);
	test_enumerate_print_list(udev_enumerate);
	udev_enumerate_unref(udev_enumerate);
	return 0;
}

int main(int argc, char *argv[])
{
	struct udev *udev = NULL;
	static const struct option options[] = {
		{ "syspath", required_argument, NULL, 'p' },
		{ "subsystem", required_argument, NULL, 's' },
		{ "debug", no_argument, NULL, 'd' },
		{ "help", no_argument, NULL, 'h' },
		{ "version", no_argument, NULL, 'V' },
		{}
	};
	const char *syspath = "/devices/virtual/mem/null";
	const char *subsystem = NULL;
	char path[1024];
	const char *str;

	udev = udev_new();
	printf("context: %p\n", udev);
	if (udev == NULL) {
		printf("no context\n");
		return 1;
	}
	udev_set_log_fn(udev, log_fn);
	printf("set log: %p\n", log_fn);

	for (;;) {
		int option;

		option = getopt_long(argc, argv, "+dhV", options, NULL);
		if (option == -1)
			break;

		switch (option) {
		case 'p':
			syspath = optarg;
			break;
		case 's':
			subsystem = optarg;
			break;
		case 'd':
			if (udev_get_log_priority(udev) < LOG_INFO)
				udev_set_log_priority(udev, LOG_INFO);
			break;
		case 'h':
			printf("--debug --syspath= --subsystem= --help\n");
			goto out;
		case 'V':
			printf("%s\n", VERSION);
			goto out;
		default:
			goto out;
		}
	}

	str = udev_get_sys_path(udev);
	printf("sys_path: '%s'\n", str);
	str = udev_get_dev_path(udev);
	printf("dev_path: '%s'\n", str);

	/* add sys path if needed */
	if (strncmp(syspath, udev_get_sys_path(udev), strlen(udev_get_sys_path(udev))) != 0) {
		snprintf(path, sizeof(path), "%s%s", udev_get_sys_path(udev), syspath);
		syspath = path;
	}

	test_device(udev, syspath);
	test_device_devnum(udev);
	test_device_subsys_name(udev);
	test_device_parents(udev, syspath);

	test_enumerate(udev, subsystem);

	test_queue(udev);

	test_monitor(udev);
out:
	udev_unref(udev);
	return 0;
}
