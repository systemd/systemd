/*
 * dev.d multipleer
 * 
 * Copyright (C) 2004 Greg Kroah-Hartman <greg@kroah.com>
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
 * 
 * Based on the klibc version of hotplug written by:
 *	Author(s) Christian Borntraeger <cborntra@de.ibm.com>
 * which was based on the shell script written by:
 *	Greg Kroah-Hartman <greg@kroah.com>
 *
 */

/* 
 * This essentially emulates the following shell script logic in C:
	DIR="/etc/dev.d"
	export DEVNODE="whatever_dev_name_udev_just_gave"
	for I in "${DIR}/$DEVNODE/"*.dev "${DIR}/$1/"*.dev "${DIR}/default/"*.dev ; do
		if [ -f $I ]; then $I $1 ; fi
	done
	exit 1;
 */

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "udev.h"
#include "udev_lib.h"
#include "logging.h"

#define HOTPLUGDIR	"/etc/dev.d"
#define SUFFIX		".dev" 
#define COMMENT_PREFIX	'#'

static void run_program(char *name)
{
	pid_t pid;

	dbg("running %s", name);

	pid = fork();

	if (pid < 0) {
		perror("fork");
		return;
	} 
	
	if (pid > 0) {
		wait(NULL);
		return;
	}

	execv(name, main_argv);
	exit(1);
}

static void execute_dir (char *dirname)
{
	DIR *directory;
	struct dirent *entry;
	char filename[NAME_SIZE];
	int name_len;

	dbg("opening %s", dirname);
	directory = opendir(dirname);
	if (!directory)
		return;

	while ((entry = readdir(directory))) {
		if (entry->d_name[0] == '\0')
			break;
		/* Don't run the files '.', '..', or hidden files, 
		 * or files that start with a '#' */
		if ((entry->d_name[0] == '.') ||
		    (entry->d_name[0] == COMMENT_PREFIX))
			continue;

		/* Nor do we run files that do not end in ".dev" */
		name_len = strlen(entry->d_name);
		if (name_len < strlen(SUFFIX))
			continue;
		if (strcmp(&entry->d_name[name_len - sizeof (SUFFIX) + 1], SUFFIX) != 0)
			continue;

		/* FIXME - need to use file_list_insert() here to run these in sorted order... */
		snprintf(filename, sizeof(filename), "%s%s", dirname, entry->d_name);
		filename[sizeof(filename)-1] = '\0';
		run_program(filename);
	}

	closedir(directory);
}

/* runs files in these directories in order:
 * 	name given by udev
 * 	subsystem
 * 	default
 */
void dev_d_send(struct udevice *dev, char *subsystem)
{
	char dirname[256];
	char devnode[NAME_SIZE];

	strfieldcpy(devnode, udev_root);
	strfieldcat(devnode, dev->name);
	setenv("DEVNODE", devnode, 1);

	snprintf(dirname, sizeof(dirname), HOTPLUGDIR "/%s/", dev->name);
	dirname[sizeof(dirname)-1] = '\0';
	execute_dir(dirname);

	snprintf(dirname, sizeof(dirname), HOTPLUGDIR "/%s/", subsystem);
	dirname[sizeof(dirname)-1] = '\0';
	execute_dir(dirname);

	strcpy(dirname, HOTPLUGDIR "/default/");
	execute_dir(dirname);
}

