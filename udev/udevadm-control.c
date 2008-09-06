/*
 * Copyright (C) 2005-2006 Kay Sievers <kay.sievers@vrfy.org>
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

#include "config.h"

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
#include "udevd.h"

int udevadm_control(struct udev *udev, int argc, char *argv[])
{
	struct udev_ctrl *uctrl;
	int rc = 1;

	/* compat values with '_' will be removed in a future release */
	static const struct option options[] = {
		{ "log-priority", 1, NULL, 'l' },
		{ "log_priority", 1, NULL, 'l' + 256 },
		{ "stop-exec-queue", 0, NULL, 's' },
		{ "stop_exec_queue", 0, NULL, 's' + 256 },
		{ "start-exec-queue", 0, NULL, 'S' },
		{ "start_exec_queue", 0, NULL, 'S' + 256},
		{ "reload-rules", 0, NULL, 'R' },
		{ "reload_rules", 0, NULL, 'R' + 256},
		{ "env", 1, NULL, 'e' },
		{ "max-childs", 1, NULL, 'm' },
		{ "max_childs", 1, NULL, 'm' + 256},
		{ "max-childs-running", 1, NULL, 'M' },
		{ "max_childs_running", 1, NULL, 'M' + 256},
		{ "help", 0, NULL, 'h' },
		{}
	};

	if (getuid() != 0) {
		fprintf(stderr, "root privileges required\n");
		goto exit;
	}

	uctrl = udev_ctrl_new_from_socket(udev, UDEVD_CTRL_SOCK_PATH);
	if (uctrl == NULL)
		goto exit;

	while (1) {
		int option;
		int i;
		char *endp;

		option = getopt_long(argc, argv, "l:sSRe:m:M:h", options, NULL);
		if (option == -1)
			break;

		if (option > 255) {
			info(udev, "udevadm control expects commands without underscore, "
			    "this will stop working in a future release\n");
			fprintf(stderr, "udevadm control expects commands without underscore, "
				"this will stop working in a future release\n");
		}

		switch (option) {
		case 'l':
		case 'l' + 256:
			i = log_priority(optarg);
			if (i < 0) {
				fprintf(stderr, "invalid number '%s'\n", optarg);
				goto exit;
			}
			udev_ctrl_set_log_level(uctrl, log_priority(optarg));
			break;
		case 's':
		case 's' + 256:
			udev_ctrl_stop_exec_queue(uctrl);
			break;
		case 'S':
		case 'S' + 256:
			udev_ctrl_start_exec_queue(uctrl);
			break;
		case 'R':
		case 'R' + 256:
			udev_ctrl_reload_rules(uctrl);
			break;
		case 'e':
			if (strchr(optarg, '=') == NULL) {
				fprintf(stderr, "expect <KEY>=<valaue> instead of '%s'\n", optarg);
				goto exit;
			}
			udev_ctrl_set_env(uctrl, optarg);
			break;
		case 'm':
		case 'm' + 256:
			i = strtoul(optarg, &endp, 0);
			if (endp[0] != '\0' || i < 1) {
				fprintf(stderr, "invalid number '%s'\n", optarg);
				goto exit;
			}
			udev_ctrl_set_max_childs(uctrl, i);
			break;
		case 'M':
		case 'M' + 256:
			i = strtoul(optarg, &endp, 0);
			if (endp[0] != '\0' || i < 1) {
				fprintf(stderr, "invalid number '%s'\n", optarg);
				goto exit;
			}
			udev_ctrl_set_max_childs_running(uctrl, i);
			break;
		case 'h':
			printf("Usage: udevadm control COMMAND\n"
				"  --log-priority=<level>   set the udev log level for the daemon\n"
				"  --stop-exec-queue        keep udevd from executing events, queue only\n"
				"  --start-exec-queue       execute events, flush queue\n"
				"  --reload-rules           reloads the rules files\n"
				"  --env=<KEY>=<value>      set a global environment variable\n"
				"  --max-childs=<N>         maximum number of childs\n"
				"  --max-childs-running=<N> maximum number of childs running at the same time\n"
				"  --help                   print this help text\n\n");
			goto exit;
		default:
			goto exit;
		}
	}

	/* compat stuff which will be removed in a future release */
	if (argv[optind] != NULL) {
		const char *arg = argv[optind];

		fprintf(stderr, "udevadm control commands requires the --<command> format, "
			"this will stop working in a future release\n");
		err(udev, "udevadm control commands requires the --<command> format, "
		    "this will stop working in a future release\n");

		if (!strncmp(arg, "log_priority=", strlen("log_priority="))) {
			udev_ctrl_set_log_level(uctrl, log_priority(&arg[strlen("log_priority=")]));
		} else if (!strcmp(arg, "stop_exec_queue")) {
			udev_ctrl_stop_exec_queue(uctrl);
		} else if (!strcmp(arg, "start_exec_queue")) {
			udev_ctrl_start_exec_queue(uctrl);
		} else if (!strcmp(arg, "reload_rules")) {
			udev_ctrl_reload_rules(uctrl);
		} else if (!strncmp(arg, "max_childs=", strlen("max_childs="))) {
			udev_ctrl_set_max_childs(uctrl, strtoul(&arg[strlen("max_childs=")], NULL, 0));
		} else if (!strncmp(arg, "max_childs_running=", strlen("max_childs_running="))) {
			udev_ctrl_set_max_childs_running(uctrl, strtoul(&arg[strlen("max_childs_running=")], NULL, 0));
		} else if (!strncmp(arg, "env", strlen("env"))) {
			udev_ctrl_set_env(uctrl, &arg[strlen("env=")]);
		} else {
			fprintf(stderr, "unrecognized command '%s'\n", arg);
			err(udev, "unrecognized command '%s'\n", arg);
		}
	}
exit:
	udev_ctrl_unref(uctrl);
	return rc;
}
