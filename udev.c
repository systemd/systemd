/*
 * udev.c
 *
 * Copyright (C) 2003-2004 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2004-2005 Kay Sievers <kay.sievers@vrfy.org>
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
 *	675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>

#include "libsysfs/sysfs/libsysfs.h"
#include "udev_libc_wrapper.h"
#include "udev.h"
#include "udev_utils.h"
#include "udev_sysfs.h"
#include "udev_version.h"
#include "udev_rules.h"
#include "logging.h"

#ifdef USE_LOG
void log_message(int priority, const char *format, ...)
{
	va_list args;

	if (priority > udev_log_priority)
		return;

	va_start(args, format);
	vsyslog(priority, format, args);
	va_end(args);
}
#endif

static void asmlinkage sig_handler(int signum)
{
	switch (signum) {
		case SIGALRM:
			exit(1);
		case SIGINT:
		case SIGTERM:
			exit(20 + signum);
	}
}

int main(int argc, char *argv[], char *envp[])
{
	struct udevice udev;
	struct udev_rules rules;
	const char *action;
	const char *devpath;
	const char *subsystem;
	struct sigaction act;
	int retval = -EINVAL;

	if (argc == 2 && strcmp(argv[1], "-V") == 0) {
		printf("%s\n", UDEV_VERSION);
		exit(0);
	}

	logging_init("udev");
	udev_init_config();
	dbg("version %s", UDEV_VERSION);

	/* set signal handlers */
	memset(&act, 0x00, sizeof(act));
	act.sa_handler = (void (*)(int)) sig_handler;
	sigemptyset (&act.sa_mask);
	act.sa_flags = 0;
	sigaction(SIGALRM, &act, NULL);
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);

	/* trigger timeout to prevent hanging processes */
	alarm(UDEV_ALARM_TIMEOUT);

	action = getenv("ACTION");
	devpath = getenv("DEVPATH");
	subsystem = getenv("SUBSYSTEM");
	/* older kernels passed the SUBSYSTEM only as argument */
	if (!subsystem && argc == 2)
		subsystem = argv[1];

	if (!action || !subsystem || !devpath) {
		err("action, subsystem or devpath missing");
		goto exit;
	}

	/* export log_priority , as called programs may want to do the same as udev */
	if (udev_log_priority) {
		char priority[32];

		sprintf(priority, "%i", udev_log_priority);
		setenv("UDEV_LOG", priority, 1);
	}

	udev_init_device(&udev, devpath, subsystem, action);
	udev_rules_init(&rules, 0);

	retval = udev_process_event(&rules, &udev);

	if (!retval && udev_run && !list_empty(&udev.run_list)) {
		struct name_entry *name_loop;

		dbg("executing run list");
		list_for_each_entry(name_loop, &udev.run_list, node) {
			if (strncmp(name_loop->name, "socket:", strlen("socket:")) == 0)
				pass_env_to_socket(&name_loop->name[strlen("socket:")], devpath, action);
			else
				execute_program(name_loop->name, udev.subsystem, NULL, 0, NULL);
		}
	}

	udev_rules_close(&rules);
	udev_cleanup_device(&udev);

exit:
	logging_close();
	return retval;
}
