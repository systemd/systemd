/*
 * udev.c
 *
 * Userspace devfs
 *
 * Copyright (C) 2003,2004 Greg Kroah-Hartman <greg@kroah.com>
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
#include <ctype.h>
#include <errno.h>
#include <signal.h>

#include "libsysfs/sysfs/libsysfs.h"
#include "udev.h"
#include "udev_lib.h"
#include "udev_version.h"
#include "logging.h"
#include "namedev.h"
#include "udevdb.h"

/* global variables */
char **main_argv;
char **main_envp;

#ifdef LOG
unsigned char logname[LOGNAME_SIZE];
void log_message(int level, const char *format, ...)
{
	va_list args;

	if (!udev_log)
		return;

	va_start(args, format);
	vsyslog(level, format, args);
	va_end(args);
}
#endif

asmlinkage static void sig_handler(int signum)
{
	switch (signum) {
		case SIGINT:
		case SIGTERM:
			udevdb_exit();
			exit(20 + signum);
		default:
			dbg("unhandled signal %d", signum);
	}
}

static char *subsystem_blacklist[] = {
	"scsi_host",
	"scsi_device",
	"usb_host",
	"pci_bus",
	"pcmcia_socket",
	""
};

int main(int argc, char *argv[], char *envp[])
{
	main_argv = argv;
	main_envp = envp;
	struct sigaction act;
	char *action;
	char *devpath = "";
	char *subsystem = "";
	int i;
	int retval = -EINVAL;
	enum {
		ADD,
		REMOVE,
		UDEVSTART,
	} act_type;

	dbg("version %s", UDEV_VERSION);

	/* initialize our configuration */
	udev_init_config();

	if (strstr(argv[0], "udevstart")) {
		act_type = UDEVSTART;
	} else {
		action = get_action();
		if (!action) {
			dbg("no action?");
			goto exit;
		}
		if (strcmp(action, "add") == 0) {
			act_type = ADD;
		} else if (strcmp(action, "remove") == 0) {
			act_type = REMOVE;
		} else {
			dbg("unknown action '%s'", action);
			goto exit;
		}

		devpath = get_devpath();
		if (!devpath) {
			dbg("no devpath?");
			goto exit;
		}
		dbg("looking at '%s'", devpath);

		/* we only care about class devices and block stuff */
		if (!strstr(devpath, "class") && !strstr(devpath, "block")) {
			dbg("not a block or class device");
			goto exit;
		}

		subsystem = get_subsystem(main_argv[1]);
		if (!subsystem) {
			dbg("no subsystem?");
			goto exit;
		}

		/* skip blacklisted subsystems */
		i = 0;
		while (subsystem_blacklist[i][0] != '\0') {
			if (strcmp(subsystem, subsystem_blacklist[i]) == 0) {
				dbg("don't care about '%s' devices", subsystem);
				goto exit;
			}
			i++;
		}
	}

	/* set signal handlers */
	act.sa_handler = sig_handler;
	sigemptyset (&act.sa_mask);
	act.sa_flags = SA_RESTART;
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);

	/* initialize udev database */
	if (udevdb_init(UDEVDB_DEFAULT) != 0) {
		dbg("unable to initialize database");
		goto exit;
	}

	switch(act_type) {
	case UDEVSTART:
		dbg("udevstart");
		namedev_init();
		udev_sleep = 0;
		retval = udev_start();
		break;
	case ADD:
		dbg("udev add");
		namedev_init();
		retval = udev_add_device(devpath, subsystem, NOFAKE);
		break;
	case REMOVE:
		dbg("udev remove");
		retval = udev_remove_device(devpath, subsystem);
	}

	udevdb_exit();

exit:
	return retval;
}
