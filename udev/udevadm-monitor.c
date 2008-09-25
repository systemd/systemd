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

static void asmlinkage sig_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM)
		udev_exit = 1;
}

int udevadm_monitor(struct udev *udev, int argc, char *argv[])
{
	struct sigaction act;
	int option;
	int env = 0;
	int print_kernel = 0;
	int print_udev = 0;
	struct udev_monitor *udev_monitor = NULL;
	struct udev_monitor *kernel_monitor = NULL;
	fd_set readfds;
	int rc = 0;

	static const struct option options[] = {
		{ "environment", 0, NULL, 'e' },
		{ "kernel", 0, NULL, 'k' },
		{ "udev", 0, NULL, 'u' },
		{ "help", 0, NULL, 'h' },
		{}
	};

	while (1) {
		option = getopt_long(argc, argv, "ekuh", options, NULL);
		if (option == -1)
			break;

		switch (option) {
		case 'e':
			env = 1;
			break;
		case 'k':
			print_kernel = 1;
			break;
		case 'u':
			print_udev = 1;
			break;
		case 'h':
			printf("Usage: udevadm monitor [--environment] [--kernel] [--udev] [--help]\n"
			       "  --env    print the whole event environment\n"
			       "  --kernel print kernel uevents\n"
			       "  --udev   print udev events\n"
			       "  --help   print this help text\n\n");
		default:
			goto out;
		}
	}

	if (!print_kernel && !print_udev) {
		print_kernel = 1;
		print_udev =1;
	}

	if (getuid() != 0 && print_kernel) {
		fprintf(stderr, "root privileges needed to subscribe to kernel events\n");
		goto out;
	}

	/* set signal handlers */
	memset(&act, 0x00, sizeof(struct sigaction));
	act.sa_handler = (void (*)(int)) sig_handler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_RESTART;
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);

	printf("monitor will print the received events for:\n");
	if (print_udev) {
		udev_monitor = udev_monitor_new_from_socket(udev, "@/org/kernel/udev/monitor");
		if (udev_monitor == NULL) {
			rc = 1;
			goto out;
		}
		if (udev_monitor_enable_receiving(udev_monitor) < 0) {
			rc = 2;
			goto out;
		}
		printf("UDEV the event which udev sends out after rule processing\n");
	}
	if (print_kernel) {
		kernel_monitor = udev_monitor_new_from_netlink(udev);
		if (kernel_monitor == NULL) {
			rc = 3;
			goto out;
		}
		if (udev_monitor_enable_receiving(kernel_monitor) < 0) {
			rc = 4;
			goto out;
		}
		printf("UEVENT the kernel uevent\n");
	}
	printf("\n");

	while (!udev_exit) {
		int fdcount;
		struct timeval tv;
		struct timezone tz;
		char timestr[64];

		FD_ZERO(&readfds);
		if (kernel_monitor != NULL)
			FD_SET(udev_monitor_get_fd(kernel_monitor), &readfds);
		if (udev_monitor != NULL)
			FD_SET(udev_monitor_get_fd(udev_monitor), &readfds);

		fdcount = select(UDEV_MAX(udev_monitor_get_fd(kernel_monitor), udev_monitor_get_fd(udev_monitor))+1,
				 &readfds, NULL, NULL, NULL);
		if (fdcount < 0) {
			if (errno != EINTR)
				fprintf(stderr, "error receiving uevent message: %s\n", strerror(errno));
			continue;
		}

		if (gettimeofday(&tv, &tz) == 0) {
			snprintf(timestr, sizeof(timestr), "%llu.%06u",
				 (unsigned long long) tv.tv_sec, (unsigned int) tv.tv_usec);
		} else
			timestr[0] = '\0';

		if ((kernel_monitor != NULL) && FD_ISSET(udev_monitor_get_fd(kernel_monitor), &readfds)) {
			struct udev_device *device = udev_monitor_receive_device(kernel_monitor);
			if (device == NULL)
				continue;
			printf("UEVENT[%s] %-8s %s (%s)\n", timestr,
			       udev_device_get_action(device),
			       udev_device_get_devpath(device),
			       udev_device_get_subsystem(device));
			if (env) {
				struct udev_list *list;

				list = udev_device_get_properties_list(device);
				while (list != NULL) {
					printf("%s=%s\n", udev_list_get_name(list), udev_list_get_value(list));
					list = udev_list_get_next(list);
				}
				printf("\n");
			}
			udev_device_unref(device);
		}

		if ((udev_monitor != NULL) && FD_ISSET(udev_monitor_get_fd(udev_monitor), &readfds)) {
			struct udev_device *device = udev_monitor_receive_device(udev_monitor);
			if (device == NULL)
				continue;
			printf("UDEV  [%s] %-8s %s (%s)\n", timestr,
			       udev_device_get_action(device),
			       udev_device_get_devpath(device),
			       udev_device_get_subsystem(device));
			if (env) {
				struct udev_list *list;

				list = udev_device_get_properties_list(device);
				while (list != NULL) {
					printf("%s=%s\n", udev_list_get_name(list), udev_list_get_value(list));
					list = udev_list_get_next(list);
				}
				printf("\n");
			}
			udev_device_unref(device);
		}
	}

out:
	udev_monitor_unref(udev_monitor);
	udev_monitor_unref(kernel_monitor);
	return rc;
}
