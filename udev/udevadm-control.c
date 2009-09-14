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
		"  --max-childs=<N>         maximum number of childs\n"
		"  --help                   print this help text\n\n");
}

int udevadm_control(struct udev *udev, int argc, char *argv[])
{
	struct udev_ctrl *uctrl = NULL;
	int rc = 1;

	/* compat values with '_' will be removed in a future release */
	static const struct option options[] = {
		{ "log-priority", required_argument, NULL, 'l' },
		{ "log_priority", required_argument, NULL, 'l' + 256 },
		{ "stop-exec-queue", no_argument, NULL, 's' },
		{ "stop_exec_queue", no_argument, NULL, 's' + 256 },
		{ "start-exec-queue", no_argument, NULL, 'S' },
		{ "start_exec_queue", no_argument, NULL, 'S' + 256},
		{ "reload-rules", no_argument, NULL, 'R' },
		{ "reload_rules", no_argument, NULL, 'R' + 256},
		{ "property", required_argument, NULL, 'p' },
		{ "env", required_argument, NULL, 'p' },
		{ "max-childs", required_argument, NULL, 'm' },
		{ "max_childs", required_argument, NULL, 'm' + 256},
		{ "help", no_argument, NULL, 'h' },
		{}
	};

	if (getuid() != 0) {
		fprintf(stderr, "root privileges required\n");
		goto exit;
	}

	uctrl = udev_ctrl_new_from_socket(udev, UDEV_CTRL_SOCK_PATH);
	if (uctrl == NULL)
		goto exit;

	while (1) {
		int option;
		int i;
		char *endp;

		option = getopt_long(argc, argv, "l:sSRp:m:M:h", options, NULL);
		if (option == -1)
			break;

		if (option > 255) {
			err(udev, "udevadm control expects commands without underscore, "
			    "this will stop working in a future release\n");
		}

		switch (option) {
		case 'l':
		case 'l' + 256:
			i = util_log_priority(optarg);
			if (i < 0) {
				fprintf(stderr, "invalid number '%s'\n", optarg);
				goto exit;
			}
			udev_ctrl_send_set_log_level(uctrl, util_log_priority(optarg));
			rc = 0;
			break;
		case 's':
		case 's' + 256:
			udev_ctrl_send_stop_exec_queue(uctrl);
			rc = 0;
			break;
		case 'S':
		case 'S' + 256:
			udev_ctrl_send_start_exec_queue(uctrl);
			rc = 0;
			break;
		case 'R':
		case 'R' + 256:
			udev_ctrl_send_reload_rules(uctrl);
			rc = 0;
			break;
		case 'p':
			if (strchr(optarg, '=') == NULL) {
				fprintf(stderr, "expect <KEY>=<value> instead of '%s'\n", optarg);
				goto exit;
			}
			udev_ctrl_send_set_env(uctrl, optarg);
			rc = 0;
			break;
		case 'm':
		case 'm' + 256:
			i = strtoul(optarg, &endp, 0);
			if (endp[0] != '\0' || i < 1) {
				fprintf(stderr, "invalid number '%s'\n", optarg);
				goto exit;
			}
			udev_ctrl_send_set_max_childs(uctrl, i);
			rc = 0;
			break;
		case 'h':
			print_help();
			rc = 0;
			goto exit;
		default:
			goto exit;
		}
	}

	/* compat stuff which will be removed in a future release */
	if (argv[optind] != NULL) {
		const char *arg = argv[optind];

		err(udev, "udevadm control commands requires the --<command> format, "
		    "this will stop working in a future release\n");

		if (!strncmp(arg, "log_priority=", strlen("log_priority="))) {
			udev_ctrl_send_set_log_level(uctrl, util_log_priority(&arg[strlen("log_priority=")]));
			rc = 0;
			goto exit;
		} else if (!strcmp(arg, "stop_exec_queue")) {
			udev_ctrl_send_stop_exec_queue(uctrl);
			rc = 0;
			goto exit;
		} else if (!strcmp(arg, "start_exec_queue")) {
			udev_ctrl_send_start_exec_queue(uctrl);
			rc = 0;
			goto exit;
		} else if (!strcmp(arg, "reload_rules")) {
			udev_ctrl_send_reload_rules(uctrl);
			rc = 0;
			goto exit;
		} else if (!strncmp(arg, "max_childs=", strlen("max_childs="))) {
			udev_ctrl_send_set_max_childs(uctrl, strtoul(&arg[strlen("max_childs=")], NULL, 0));
			rc = 0;
			goto exit;
		} else if (!strncmp(arg, "env", strlen("env"))) {
			udev_ctrl_send_set_env(uctrl, &arg[strlen("env=")]);
			rc = 0;
			goto exit;
		}
	}

	if (rc != 0) {
		err(udev, "unrecognized command\n");
	}
exit:
	udev_ctrl_unref(uctrl);
	return rc;
}
