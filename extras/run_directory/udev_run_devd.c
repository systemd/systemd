/*
 * udev_run_devd.c - directory multiplexer
 *
 * Copyright (C) 2005 Kay Sievers <kay@vrfy.org>
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "../../udev.h"
#include "run_directory.h"


#ifdef USE_LOG
void log_message (int priority, const char *format, ...)
{
	va_list args;
	static int udev_log = -1;

	if (udev_log == -1) {
		const char *value;

		value = getenv("UDEV_LOG");
		if (value)
			udev_log = log_priority(value);
		else
			udev_log = LOG_ERR;
	}

	if (priority > udev_log)
		return;

	va_start(args, format);
	vsyslog(priority, format, args);
	va_end(args);
}
#endif

int main(int argc, char *argv[], char *envp[])
{
	char dirname[NAME_SIZE];
	const char *devname;
	const char *my_devname;
	const char *subsystem;
	int fd;

	devname = getenv("DEVNAME");
	if (devname == NULL)
		exit(0);
	/*
	 * Hack, we are assuming that the device nodes are in /dev,
	 * if not, this will not work, but you should be using the
	 * RUN= rule anyway...
	 */
	my_devname = strstr(devname, "/dev/");
	if (my_devname != NULL)
		my_devname = &my_devname[5];
	else
		my_devname = devname;

	subsystem = argv[1];
	logging_init("udev_run_devd");

	fd = open("/dev/null", O_RDWR);
	if (fd >= 0) {
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDIN_FILENO);
		dup2(fd, STDERR_FILENO);
		close(fd);
	}
	dbg("running dev.d directory");

	sprintf(dirname, "/etc/dev.d/%s", my_devname);
	run_directory(dirname, ".dev", subsystem);
	sprintf(dirname, "/etc/dev.d/%s", subsystem);
	run_directory(dirname, ".dev", subsystem);
	run_directory("/etc/dev.d/default", ".dev", subsystem);

	exit(0);
}
