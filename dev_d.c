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
#include <unistd.h>
#include "udev.h"
#include "udev_lib.h"
#include "logging.h"

#define DEVD_DIR			"/etc/dev.d/"
#define DEVD_SUFFIX			".dev"

static int run_program(char *name)
{
	pid_t pid;

	dbg("running %s", name);

	pid = fork();
	switch (pid) {
	case 0:
		/* child */
		execv(name, main_argv);
		dbg("exec of child failed");
		exit(1);
	case -1:
		dbg("fork of child failed");
		break;
		return -1;
	default:
		wait(NULL);
	}

	return 0;
}

/* 
 * runs files in these directories in order:
 * 	<node name given by udev>/
 * 	subsystem/
 * 	default/
 */
void dev_d_send(struct udevice *dev, char *subsystem, char *devpath)
{
	char dirname[256];
	char devname[NAME_SIZE];

	if (udev_dev_d == 0)
		return;

	if (dev->type == 'b' || dev->type == 'c') {
		strfieldcpy(devname, udev_root);
		strfieldcat(devname, dev->name);
	} else if (dev->type == 'n') {
		strfieldcpy(devname, dev->name);
		setenv("DEVPATH", devpath, 1);
	}
	setenv("DEVNAME", devname, 1);
	dbg("DEVNAME='%s'", devname);

	strcpy(dirname, DEVD_DIR);
	strfieldcat(dirname, dev->name);
	call_foreach_file(run_program, dirname, DEVD_SUFFIX);

	strcpy(dirname, DEVD_DIR);
	strfieldcat(dirname, subsystem);
	call_foreach_file(run_program, dirname, DEVD_SUFFIX);

	strcpy(dirname, DEVD_DIR "default");
	call_foreach_file(run_program, dirname, DEVD_SUFFIX);
}
