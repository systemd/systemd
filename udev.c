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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <signal.h>

#include "libsysfs/sysfs/libsysfs.h"
#include "udev.h"
#include "udev_version.h"
#include "udev_dbus.h"
#include "logging.h"
#include "namedev.h"
#include "udevdb.h"

/* global variables */
char **main_argv;
char **main_envp;

#ifdef LOG
unsigned char logname[42];
void log_message (int level, const char *format, ...)
{
	va_list	args;

	if (!udev_log)
		return;

	va_start(args, format);
	vsyslog(level, format, args);
	va_end(args);
}
#endif

static void sig_handler(int signum)
{
	switch (signum) {
		case SIGINT:
		case SIGTERM:
			sysbus_disconnect();
			udevdb_exit();
			exit(20 + signum);
		default:
			dbg("unhandled signal");
	}
}

static inline char *get_action(void)
{
	char *action;

	action = getenv("ACTION");
	return action;
}

static inline char *get_devpath(void)
{
	char *devpath;

	devpath = getenv("DEVPATH");
	return devpath;
}

static inline char *get_seqnum(void)
{
	char *seqnum;

	seqnum = getenv("SEQNUM");
	return seqnum;
}

static char *subsystem_blacklist[] = {
	"net",
	"scsi_host",
	"scsi_device",
	"usb_host",
	"pci_bus",
	"",
};

static int udev_hotplug(int argc, char **argv)
{
	char *action;
	char *devpath;
	char *subsystem;
	int retval = -EINVAL;
	int i;
	struct sigaction act;

	action = get_action();
	if (!action) {
		dbg ("no action?");
		goto exit;
	}

	devpath = get_devpath();
	if (!devpath) {
		dbg ("no devpath?");
		goto exit;
	}
	dbg("looking at '%s'", devpath);

	/* we only care about class devices and block stuff */
	if (!strstr(devpath, "class") &&
	    !strstr(devpath, "block")) {
		dbg("not a block or class device");
		goto exit;
	}

	/* skip blacklisted subsystems */
	subsystem = argv[1];
	i = 0;
	while (subsystem_blacklist[i][0] != '\0') {
		if (strcmp(subsystem, subsystem_blacklist[i]) == 0) {
			dbg("don't care about '%s' devices", subsystem);
			goto exit;
		}
		i++;
	}

	/* connect to the system message bus */
	sysbus_connect();

	/* initialize our configuration */
	udev_init_config();

	/* initialize udev database */
	retval = udevdb_init(UDEVDB_DEFAULT);
	if (retval != 0) {
		dbg("unable to initialize database");
		goto exit_sysbus;
	}

	/* set up a default signal handler for now */
	act.sa_handler = sig_handler;
	sigemptyset (&act.sa_mask);
	act.sa_flags = SA_RESTART;
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);

	/* initialize the naming deamon */
	namedev_init();

	if (strcmp(action, "add") == 0)
		retval = udev_add_device(devpath, subsystem, 0);

	else if (strcmp(action, "remove") == 0)
		retval = udev_remove_device(devpath, subsystem);

	else {
		dbg("unknown action '%s'", action);
		retval = -EINVAL;
	}
	udevdb_exit();

exit_sysbus:
	/* disconnect from the system message bus */
	sysbus_disconnect();

exit:
	if (retval > 0)
		retval = 0;

	return -retval;
}

int main(int argc, char **argv, char **envp)
{
	main_argv = argv;
	main_envp = envp;

	init_logging("udev");
	dbg("version %s", UDEV_VERSION);

	return udev_hotplug(argc, argv);
}


