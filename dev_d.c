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
#include "udevdb.h"
#include "logging.h"

#define DEVD_DIR			"/etc/dev.d/"
#define DEVD_SUFFIX			".dev"

static int run_program(char *name)
{
	pid_t pid;
	int fd;
	char *argv[3];

	dbg("running %s", name);

	pid = fork();
	switch (pid) {
	case 0:
		/* child */
		udevdb_exit();  /* close udevdb */
		fd = open("/dev/null", O_RDWR);
		if ( fd >= 0) {
			dup2(fd, STDOUT_FILENO);
			dup2(fd, STDIN_FILENO);
			dup2(fd, STDERR_FILENO);
		}
		close(fd);

		argv[0] = name;
		argv[1] = main_argv[1];
		argv[2] = NULL;

		execv(name, argv);
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
void dev_d_execute(struct udevice *udev)
{
	char dirname[PATH_MAX];
	char devname[NAME_SIZE];
	char *temp;

	/* skip if UDEV_NO_DEVD is set */
	if (udev_dev_d == 0)
		return;

	/* skip if udev did nothing, like unchanged netif or no "dev" file */
	if (udev->devname[0] == '\0')
		return;

	/* add the node name or the netif name to the environment */
	setenv("DEVNAME", udev->devname, 1);
	dbg("DEVNAME='%s'", udev->devname);

	strfieldcpy(devname, udev->name);

	/* Chop the device name up into pieces based on '/' */
	temp = strchr(devname, '/');
	while (temp != NULL) {
		temp[0] = '\0';
		strcpy(dirname, DEVD_DIR);
		strfieldcat(dirname, devname);
		call_foreach_file(run_program, dirname, DEVD_SUFFIX);

		temp[0] = '/';
		++temp;
		temp = strchr(temp, '/');
	}

	strcpy(dirname, DEVD_DIR);
	strfieldcat(dirname, udev->name);
	call_foreach_file(run_program, dirname, DEVD_SUFFIX);

	strcpy(dirname, DEVD_DIR);
	strfieldcat(dirname, udev->subsystem);
	call_foreach_file(run_program, dirname, DEVD_SUFFIX);

	strcpy(dirname, DEVD_DIR "default");
	call_foreach_file(run_program, dirname, DEVD_SUFFIX);
}
