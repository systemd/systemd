/*
 * dev_d.c - dev.d/ multiplexer
 * 
 * Copyright (C) 2004 Greg Kroah-Hartman <greg@kroah.com>
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
 */

/*
 * This essentially emulates the following shell script logic in C:
 *	DIR="/etc/dev.d"
 *	export DEVNAME="whatever_dev_name_udev_just_gave"
 *	for I in "${DIR}/$DEVNAME/"*.dev "${DIR}/$1/"*.dev "${DIR}/default/"*.dev ; do
 *		if [ -f $I ]; then $I $1 ; fi
 *	done
 *	exit 1;
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "udev.h"
#include "udev_lib.h"
#include "logging.h"

static int run_program(const char *filename, void *data)
{
	pid_t pid;
	int fd;
	struct udevice *udev = data;

	dbg("running %s", filename);

	pid = fork();
	switch (pid) {
	case 0:
		/* child */
		fd = open("/dev/null", O_RDWR);
		if ( fd >= 0) {
			dup2(fd, STDOUT_FILENO);
			dup2(fd, STDIN_FILENO);
			dup2(fd, STDERR_FILENO);
		}
		close(fd);

		execl(filename, filename, udev->subsystem, NULL);
		dbg("exec of child failed");
		_exit(1);
	case -1:
		dbg("fork of child failed");
		break;
		return -1;
	default:
		waitpid(pid, NULL, 0);
	}

	return 0;
}

/* 
 * runs files in these directories in order:
 * 	<node name given by udev>/
 * 	subsystem/
 * 	default/
 */
void dev_d_execute(struct udevice *udev, const char *basedir, const char *suffix)
{
	char dirname[PATH_MAX];
	char devname[NAME_SIZE];
	char *temp;

	/* skip if UDEV_NO_DEVD is set */
	if (udev_dev_d == 0)
		return;

	strfieldcpy(devname, udev->name);

	/* chop the device name up into pieces based on '/' */
	temp = strchr(devname, '/');
	while (temp != NULL) {
		temp[0] = '\0';
		snprintf(dirname, PATH_MAX, "%s/%s", basedir, devname);
		dirname[PATH_MAX-1] = '\0';
		call_foreach_file(run_program, dirname, suffix, udev);

		temp[0] = '/';
		++temp;
		temp = strchr(temp, '/');
	}

	if (udev->name[0] != '\0') {
		snprintf(dirname, PATH_MAX, "%s/%s", basedir, udev->name);
		dirname[PATH_MAX-1] = '\0';
		call_foreach_file(run_program, dirname, suffix, udev);
	}

	if (udev->subsystem[0] != '\0') {
		snprintf(dirname, PATH_MAX, "%s/%s", basedir, udev->subsystem);
		dirname[PATH_MAX-1] = '\0';
		call_foreach_file(run_program, dirname, suffix, udev);
	}

	snprintf(dirname, PATH_MAX, "%s/default", basedir);
	dirname[PATH_MAX-1] = '\0';
	call_foreach_file(run_program, dirname, suffix, udev);
}
