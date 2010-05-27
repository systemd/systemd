/*
 * Copyright (C) 2005-2008 Kay Sievers <kay.sievers@vrfy.org>
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
 */

#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>

#include "udev.h"

static void print_help(void)
{
	printf("Usage: udevadm control COMMAND\n"
		"  --log-priority=<level>   set the udev log level for the daemon\n"
		"  --stop-exec-queue        keep udevd from executing events, queue only\n"
		"  --start-exec-queue       execute events, flush queue\n"
		"  --reload-rules           reloads the rules files\n"
		"  --property=<KEY>=<value> set a global property for all events\n"
		"  --children-max=<N>       maximum number of children\n"
		"  --help                   print this help text\n\n");
}

int udevadm_control(struct udev *udev, int argc, char *argv[])
{
	struct udev_ctrl *uctrl = NULL;
	int rc = 1;

	/* compat values with '_' will be removed in a future release */
	static const struct option options[] = {
		{ "log-priority", required_argument, NULL, 'l' },
		{ "stop-exec-queue", no_argument, NULL, 's' },
		{ "start-exec-queue", no_argument, NULL, 'S' },
		{ "reload-rules", no_argument, NULL, 'R' },
		{ "property", required_argument, NULL, 'p' },
		{ "env", required_argument, NULL, 'p' },
		{ "children-max", required_argument, NULL, 'm' },
		{ "help", no_argument, NULL, 'h' },
		{}
	};

	if (getuid() != 0) {
		fprintf(stderr, "root privileges required\n");
		return 1;
	}

	uctrl = udev_ctrl_new_from_socket(udev, UDEV_CTRL_SOCK_PATH);
	if (uctrl == NULL)
		return 2;

	for (;;) {
		int option;
		int i;
		char *endp;

		option = getopt_long(argc, argv, "l:sSRp:m:M:h", options, NULL);
		if (option == -1)
			break;

		switch (option) {
		case 'l':
			i = util_log_priority(optarg);
			if (i < 0) {
				fprintf(stderr, "invalid number '%s'\n", optarg);
				goto exit;
			}
			if (udev_ctrl_send_set_log_level(uctrl, util_log_priority(optarg)) < 0)
				rc = 2;
			else
				rc = 0;
			break;
		case 's':
			if (udev_ctrl_send_stop_exec_queue(uctrl) < 0)
				rc = 2;
			else
				rc = 0;
			break;
		case 'S':
			if (udev_ctrl_send_start_exec_queue(uctrl) < 0)
				rc = 2;
			else
				rc = 0;
			break;
		case 'R':
			if (udev_ctrl_send_reload_rules(uctrl) < 0)
				rc = 2;
			else
				rc = 0;
			break;
		case 'p':
			if (strchr(optarg, '=') == NULL) {
				fprintf(stderr, "expect <KEY>=<value> instead of '%s'\n", optarg);
				goto exit;
			}
			if (udev_ctrl_send_set_env(uctrl, optarg) < 0)
				rc = 2;
			else
				rc = 0;
			break;
		case 'm':
			i = strtoul(optarg, &endp, 0);
			if (endp[0] != '\0' || i < 1) {
				fprintf(stderr, "invalid number '%s'\n", optarg);
				goto exit;
			}
			if (udev_ctrl_send_set_children_max(uctrl, i) < 0)
				rc = 2;
			else
				rc = 0;
			break;
		case 'h':
			print_help();
			rc = 0;
			break;
		}
	}

	if (rc == 1)
		err(udev, "unrecognized command\n");
exit:
	udev_ctrl_unref(uctrl);
	return rc;
}
