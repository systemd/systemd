/*
 * udevstart.c
 *
 * Copyright (C) 2004 Greg Kroah-Hartman <greg@kroah.com>
 * 
 * Quick and dirty way to populate a /dev with udev if your system
 * does not have access to a shell.  Based originally on a patch to udev 
 * from Harald Hoyer <harald@redhat.com>
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
#include <dirent.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>

#include "logging.h"
#include "udev_lib.h"


#ifdef LOG
unsigned char logname[LOGNAME_SIZE];
void log_message(int level, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vsyslog(level, format, args);
	va_end(args);
}
#endif


#define MAX_PATHLEN		1024
#define SYSBLOCK		"/sys/block"
#define SYSCLASS		"/sys/class"
#define UDEV_BIN		"/sbin/udev"

static void udev_exec(const char *path, const char* subsystem)
{
	pid_t pid;
	char action[] = "ACTION=add";
	char devpath[MAX_PATHLEN];
	char nosleep[] = "UDEV_NO_SLEEP=1";
	char *env[] = { action, devpath, nosleep, NULL };

	strcpy(devpath, "DEVPATH=");
	strfieldcat(devpath, path);

	pid = fork();
	switch (pid) {
	case 0:
		/* child */
		execle(UDEV_BIN, "udev", subsystem, NULL, env);
		dbg("exec of child failed");
		exit(1);
		break;
	case -1:
		dbg("fork of child failed");
		break;
	default:
		wait(NULL);
	}
}

static void udev_scan(void)
{
	char *devpath;
	DIR *dir;
	struct dirent *dent;

	devpath = "block";
	dir = opendir(SYSBLOCK);
	if (dir != NULL) {
		for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
			char dirname[MAX_PATHLEN];
			DIR *dir2;
			struct dirent *dent2;

			if ((strcmp(dent->d_name, ".") == 0) ||
			    (strcmp(dent->d_name, "..") == 0))
				continue;

			snprintf(dirname, MAX_PATHLEN, "/block/%s", dent->d_name);
			dirname[MAX_PATHLEN-1] = '\0';
			udev_exec(dirname, "block");

			snprintf(dirname, MAX_PATHLEN, "%s/%s", SYSBLOCK, dent->d_name);
			dir2 = opendir(dirname);
			if (dir2 != NULL) {
				for (dent2 = readdir(dir2); dent2 != NULL; dent2 = readdir(dir2)) {
					char dirname2[MAX_PATHLEN];
					DIR *dir3;
					struct dirent *dent3;

					if ((strcmp(dent2->d_name, ".") == 0) ||
					    (strcmp(dent2->d_name, "..") == 0))
						continue;

					snprintf(dirname2, MAX_PATHLEN, "%s/%s", dirname, dent2->d_name);
					dirname2[MAX_PATHLEN-1] = '\0';

					dir3 = opendir(dirname2);
					if (dir3 != NULL) {
						for (dent3 = readdir(dir3); dent3 != NULL; dent3 = readdir(dir3)) {
							char filename[MAX_PATHLEN];

							if (strcmp(dent3->d_name, "dev") == 0) {
								snprintf(filename, MAX_PATHLEN, "/block/%s/%s",
									 dent->d_name, dent2->d_name);
								filename[MAX_PATHLEN-1] = '\0';
								udev_exec(filename, "block");
							}
						}
					}
				}
			}
		}
	}

	devpath = "class";
	dir = opendir(SYSCLASS);
	if (dir != NULL) {
		for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
			char dirname[MAX_PATHLEN];
			DIR *dir2;
			struct dirent *dent2;

			if ((strcmp(dent->d_name, ".") == 0) ||
			    (strcmp(dent->d_name, "..") == 0))
				continue;

			snprintf(dirname, MAX_PATHLEN, "%s/%s", SYSCLASS, dent->d_name);
			dirname[MAX_PATHLEN] = '\0';
			dir2 = opendir(dirname);
			if (dir2 != NULL) {
				for (dent2 = readdir(dir2); dent2 != NULL; dent2 = readdir(dir2)) {
					char dirname2[MAX_PATHLEN-1];
					DIR *dir3;
					struct dirent *dent3;

					if ((strcmp(dent2->d_name, ".") == 0) ||
					    (strcmp(dent2->d_name, "..") == 0))
						continue;

					snprintf(dirname2, MAX_PATHLEN, "%s/%s", dirname, dent2->d_name);
					dirname2[MAX_PATHLEN-1] = '\0';

					dir3 = opendir(dirname2);
					if (dir3 != NULL) {
						for (dent3 = readdir(dir3); dent3 != NULL; dent3 = readdir(dir3)) {
							char filename[MAX_PATHLEN];

							if (strcmp(dent3->d_name, "dev") == 0) {
								snprintf(filename, MAX_PATHLEN, "/class/%s/%s",
									 dent->d_name, dent2->d_name);
								filename[MAX_PATHLEN-1] = '\0';
								udev_exec(filename, dent->d_name);
							}
						}
					}
				}
			}
		}
	}
}


int main(int argc, char *argv[], char *envp[])
{
	init_logging("udevstart");

	udev_scan();

	return 0;
}
