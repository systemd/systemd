/*
 * Copyright (C) 2004-2008 Kay Sievers <kay.sievers@vrfy.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <linux/types.h>
#include <linux/netlink.h>

#include "udev.h"

static int udev_exit;

static void sig_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM)
		udev_exit = 1;
}

static void print_device(struct udev_device *device, const char *source, int prop)
{
	struct timeval tv;
	struct timezone tz;

	gettimeofday(&tv, &tz);
	printf("%-6s[%llu.%06u] %-8s %s (%s)\n",
	       source,
	       (unsigned long long) tv.tv_sec, (unsigned int) tv.tv_usec,
	       udev_device_get_action(device),
	       udev_device_get_devpath(device),
	       udev_device_get_subsystem(device));
	if (prop) {
		struct udev_list_entry *list_entry;

		udev_list_entry_foreach(list_entry, udev_device_get_properties_list_entry(device))
			printf("%s=%s\n",
			       udev_list_entry_get_name(list_entry),
			       udev_list_entry_get_value(list_entry));
		printf("\n");
	}
}

int udevadm_monitor(struct udev *udev, int argc, char *argv[])
{
	struct sigaction act;
	int option;
	int prop = 0;
	int print_kernel = 0;
	int print_udev = 0;
	struct udev_list_node subsystem_match_list;
	struct udev_monitor *udev_monitor = NULL;
	struct udev_monitor *kernel_monitor = NULL;
	fd_set readfds;
	int rc = 0;

	static const struct option options[] = {
		{ "property", no_argument, NULL, 'p' },
		{ "environment", no_argument, NULL, 'e' },
		{ "kernel", no_argument, NULL, 'k' },
		{ "udev", no_argument, NULL, 'u' },
		{ "subsystem-match", required_argument, NULL, 's' },
		{ "help", no_argument, NULL, 'h' },
		{}
	};

	udev_list_init(&subsystem_match_list);
	while (1) {
		option = getopt_long(argc, argv, "epkus:h", options, NULL);
		if (option == -1)
			break;

		switch (option) {
		case 'p':
		case 'e':
			prop = 1;
			break;
		case 'k':
			print_kernel = 1;
			break;
		case 'u':
			print_udev = 1;
			break;
		case 's':
			{
				char subsys[UTIL_NAME_SIZE];
				char *devtype;

				util_strscpy(subsys, sizeof(subsys), optarg);
				devtype = strchr(subsys, ':');
				if (devtype != NULL) {
					devtype[0] = '\0';
					devtype++;
				}
				udev_list_entry_add(udev, &subsystem_match_list, subsys, devtype, 0, 0);
				break;
			}
		case 'h':
			printf("Usage: udevadm monitor [--property] [--kernel] [--udev] [--help]\n"
			       "  --property                    print the event properties\n"
			       "  --kernel                      print kernel uevents\n"
			       "  --udev                        print udev events\n"
			       "  --subsystem-match=<subsystem> filter events\n"
			       "  --help\n\n");
		default:
			goto out;
		}
	}

	if (!print_kernel && !print_udev) {
		print_kernel = 1;
		print_udev =1;
	}

	/* set signal handlers */
	memset(&act, 0x00, sizeof(struct sigaction));
	act.sa_handler = sig_handler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_RESTART;
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);

	printf("monitor will print the received events for:\n");
	if (print_udev) {
		struct udev_list_entry *entry;

		udev_monitor = udev_monitor_new_from_netlink(udev, "udev");
		if (udev_monitor == NULL) {
			fprintf(stderr, "error: unable to create netlink socket\n");
			rc = 1;
			goto out;
		}

		udev_list_entry_foreach(entry, udev_list_get_entry(&subsystem_match_list)) {
			const char *subsys = udev_list_entry_get_name(entry);
			const char *devtype = udev_list_entry_get_value(entry);

			if (udev_monitor_filter_add_match_subsystem_devtype(udev_monitor, subsys, devtype) < 0)
				fprintf(stderr, "error: unable to apply subsystem filter '%s'\n", subsys);
		}

		if (udev_monitor_enable_receiving(udev_monitor) < 0) {
			fprintf(stderr, "error: unable to subscribe to udev events\n");
			rc = 2;
			goto out;
		}
		printf("UDEV - the event which udev sends out after rule processing\n");
	}
	if (print_kernel) {
		struct udev_list_entry *entry;

		kernel_monitor = udev_monitor_new_from_netlink(udev, "kernel");
		if (kernel_monitor == NULL) {
			fprintf(stderr, "error: unable to create netlink socket\n");
			rc = 3;
			goto out;
		}

		udev_list_entry_foreach(entry, udev_list_get_entry(&subsystem_match_list)) {
			const char *subsys = udev_list_entry_get_name(entry);

			if (udev_monitor_filter_add_match_subsystem_devtype(kernel_monitor, subsys, NULL) < 0)
				fprintf(stderr, "error: unable to apply subsystem filter '%s'\n", subsys);
		}

		if (udev_monitor_enable_receiving(kernel_monitor) < 0) {
			fprintf(stderr, "error: unable to subscribe to kernel events\n");
			rc = 4;
			goto out;
		}
		printf("KERNEL - the kernel uevent\n");
	}
	printf("\n");

	while (!udev_exit) {
		int fdcount;

		FD_ZERO(&readfds);
		if (kernel_monitor != NULL)
			FD_SET(udev_monitor_get_fd(kernel_monitor), &readfds);
		if (udev_monitor != NULL)
			FD_SET(udev_monitor_get_fd(udev_monitor), &readfds);

		fdcount = select(MAX(udev_monitor_get_fd(kernel_monitor), udev_monitor_get_fd(udev_monitor))+1,
				 &readfds, NULL, NULL, NULL);
		if (fdcount < 0) {
			if (errno != EINTR)
				fprintf(stderr, "error receiving uevent message: %m\n");
			continue;
		}

		if ((kernel_monitor != NULL) && FD_ISSET(udev_monitor_get_fd(kernel_monitor), &readfds)) {
			struct udev_device *device;

			device = udev_monitor_receive_device(kernel_monitor);
			if (device == NULL)
				continue;
			print_device(device, "KERNEL", prop);
			udev_device_unref(device);
		}

		if ((udev_monitor != NULL) && FD_ISSET(udev_monitor_get_fd(udev_monitor), &readfds)) {
			struct udev_device *device;

			device = udev_monitor_receive_device(udev_monitor);
			if (device == NULL)
				continue;
			print_device(device, "UDEV", prop);
			udev_device_unref(device);
		}
	}

out:
	udev_monitor_unref(udev_monitor);
	udev_monitor_unref(kernel_monitor);
	udev_list_cleanup_entries(udev, &subsystem_match_list);
	return rc;
}
