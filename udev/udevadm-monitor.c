/*
 * Copyright (C) 2004-2006 Kay Sievers <kay.sievers@vrfy.org>
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
 * 
 *	This program is distributed in the hope that it will be useful, but
 *	WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *	General Public License for more details.
 * 
 *	You should have received a copy of the GNU General Public License along
 *	with this program; if not, write to the Free Software Foundation, Inc.,
 *	51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
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

static int uevent_netlink_sock = -1;
static int udev_exit;

static int init_uevent_netlink_sock(void)
{
	struct sockaddr_nl snl;
	int err;

	memset(&snl, 0x00, sizeof(struct sockaddr_nl));
	snl.nl_family = AF_NETLINK;
	snl.nl_pid = getpid();
	snl.nl_groups = 1;

	uevent_netlink_sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
	if (uevent_netlink_sock == -1) {
		fprintf(stderr, "error getting socket: %s\n", strerror(errno));
		return -1;
	}

	err = bind(uevent_netlink_sock, (struct sockaddr *) &snl,
		      sizeof(struct sockaddr_nl));
	if (err < 0) {
		fprintf(stderr, "bind failed: %s\n", strerror(errno));
		close(uevent_netlink_sock);
		uevent_netlink_sock = -1;
		return -1;
	}

	return 0;
}

static void asmlinkage sig_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM)
		udev_exit = 1;
}

static const char *search_key(const char *searchkey, const char *buf, size_t buflen)
{
	size_t bufpos = 0;
	size_t searchkeylen = strlen(searchkey);

	while (bufpos < buflen) {
		const char *key;
		int keylen;

		key = &buf[bufpos];
		keylen = strlen(key);
		if (keylen == 0)
			break;
		 if ((strncmp(searchkey, key, searchkeylen) == 0) && key[searchkeylen] == '=')
			return &key[searchkeylen + 1];
		bufpos += keylen + 1;
	}
	return NULL;
}

int udevadm_monitor(struct udev *udev, int argc, char *argv[])
{
	struct sigaction act;
	int option;
	int env = 0;
	int print_kernel = 0;
	int print_udev = 0;
	struct udev_monitor *udev_monitor = NULL;
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
		if (init_uevent_netlink_sock() < 0) {
			rc = 3;
			goto out;
		}
		printf("UEVENT the kernel uevent\n");
	}
	printf("\n");

	while (!udev_exit) {
		char buf[UEVENT_BUFFER_SIZE*2];
		ssize_t buflen;
		ssize_t bufpos;
		ssize_t keys;
		int fdcount;
		struct timeval tv;
		struct timezone tz;
		char timestr[64];
		const char *source = NULL;
		const char *devpath, *action, *subsys;

		buflen = 0;
		FD_ZERO(&readfds);
		if (uevent_netlink_sock >= 0)
			FD_SET(uevent_netlink_sock, &readfds);
		if (udev_monitor != NULL)
			FD_SET(udev_monitor_get_fd(udev_monitor), &readfds);

		fdcount = select(UDEV_MAX(uevent_netlink_sock, udev_monitor_get_fd(udev_monitor))+1,
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

		if ((uevent_netlink_sock >= 0) && FD_ISSET(uevent_netlink_sock, &readfds)) {
			buflen = recv(uevent_netlink_sock, &buf, sizeof(buf), 0);
			if (buflen <= 0) {
				fprintf(stderr, "error receiving uevent message: %s\n", strerror(errno));
				continue;
			}
			source = "UEVENT";
		}

		if ((udev_monitor != NULL) && FD_ISSET(udev_monitor_get_fd(udev_monitor), &readfds)) {
			buflen = recv(udev_monitor_get_fd(udev_monitor), &buf, sizeof(buf), 0);
			if (buflen <= 0) {
				fprintf(stderr, "error receiving udev message: %s\n", strerror(errno));
				continue;
			}
			source = "UDEV  ";
		}

		if (buflen == 0)
			continue;

		keys = strlen(buf) + 1; /* start of payload */
		devpath = search_key("DEVPATH", &buf[keys], buflen);
		action = search_key("ACTION", &buf[keys], buflen);
		subsys = search_key("SUBSYSTEM", &buf[keys], buflen);
		printf("%s[%s] %-8s %s (%s)\n", source, timestr, action, devpath, subsys);

		/* print environment */
		bufpos = keys;
		if (env) {
			while (bufpos < buflen) {
				int keylen;
				char *key;

				key = &buf[bufpos];
				keylen = strlen(key);
				if (keylen == 0)
					break;
				printf("%s\n", key);
				bufpos += keylen + 1;
			}
			printf("\n");
		}
	}

out:
	udev_monitor_unref(udev_monitor);
	if (uevent_netlink_sock >= 0)
		close(uevent_netlink_sock);

	return rc;
}
