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
#include <signal.h>
#include <dirent.h>
#include <sys/wait.h>

#include "logging.h"


#ifdef LOG
unsigned char logname[42];
void log_message(int level, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vsyslog(level, format, args);
	va_end(args);
}
#endif


#define MAX_PATHLEN	1024
#define SYSBLOCK	"/sys/block"
#define SYSCLASS	"/sys/class"

static int execute_udev(char *path, char *value, int len)
{
	int retval;
	int res;
	int status;
	int fds[2];
	pid_t pid;
	int value_set = 0;
	char buffer[255];
	char *pos;

	retval = pipe(fds);
	if (retval != 0) {
		dbg("pipe failed");
		return -1;
	}
	pid = fork();
	switch(pid) {
	case 0:
		/* child */
		close(STDOUT_FILENO);

		/* dup write side of pipe to STDOUT */
		dup(fds[1]);

		dbg("executing /sbin/udev '%s'", path);
		retval = execl("/sbin/udev", "/sbin/udev", path, NULL);

		info("execution of '%s' failed", path);
		exit(1);
	case -1:
		dbg("fork failed");
		return -1;
	default:
		/* parent reads from fds[0] */
		close(fds[1]);
		retval = 0;
		while (1) {
			res = read(fds[0], buffer, sizeof(buffer) - 1);
			if (res <= 0)
				break;
			buffer[res] = '\0';
			if (res > len) {
				dbg("result len %d too short", len);
				retval = -1;
			}
			if (value_set) {
				dbg("result value already set");
				retval = -1;
			} else {
				value_set = 1;
				strncpy(value, buffer, len);
				pos = value + strlen(value)-1;
				if (pos[0] == '\n')
					pos[0] = '\0';
				dbg("result is '%s'", value);
			}
		}
		close(fds[0]);
		res = wait(&status);
		if (res < 0) {
			dbg("wait failed result %d", res);
			retval = -1;
		}

		if (!WIFEXITED(status) || (WEXITSTATUS(status) != 0)) {
			dbg("exec program status 0x%x", status);
			retval = -1;
		}
	}
	return retval;
}

static int udev_scan(void)
{
	char           *devpath;
	DIR            *dir;
	struct dirent  *dent;
	int             retval = -EINVAL;
	char scratch[200];

	devpath = "block";
	dir = opendir(SYSBLOCK);
	if (dir) {
		for (dent = readdir(dir); dent; dent = readdir(dir)) {
			char            dirname[MAX_PATHLEN];
			DIR            *dir2;
			struct dirent  *dent2;
			if ((strcmp(dent->d_name, ".") == 0)
			    || (strcmp(dent->d_name, "..") == 0))
				continue;

			snprintf(dirname, MAX_PATHLEN, "/block/%s", dent->d_name);

			setenv("DEVPATH", dirname, 1);
			dbg("udev block, 'DEVPATH' = '%s'", dirname);
			execute_udev("block", scratch, sizeof(scratch));

			snprintf(dirname, MAX_PATHLEN, "%s/%s", SYSBLOCK, dent->d_name);

			dir2 = opendir(dirname);
			if (dir2) {
				for (dent2 = readdir(dir2); dent2; dent2 = readdir(dir2)) {
					char            dirname2[MAX_PATHLEN];
					DIR            *dir3;
					struct dirent  *dent3;

					if ((strcmp(dent2->d_name, ".") == 0) ||
					    (strcmp(dent2->d_name, "..") == 0))
						continue;

					snprintf(dirname2, MAX_PATHLEN, "%s/%s", dirname, dent2->d_name);

					dir3 = opendir(dirname2);
					if (dir3) {
						for (dent3 = readdir(dir3); dent3; dent3 = readdir(dir3)) {
							char filename[MAX_PATHLEN];

							if (strcmp(dent3->d_name, "dev") == 0) {
								snprintf(filename, MAX_PATHLEN, "/block/%s/%s", dent->d_name, dent2->d_name);
								setenv("DEVPATH", filename, 1);
								dbg("udev block, 'DEVPATH' = '%s'", filename);
								execute_udev("block", scratch, sizeof(scratch));
							}
						}
					}
				}
			}
		}
	}

	devpath = "class";
	dir = opendir(SYSCLASS);
	if (dir) {
		for (dent = readdir(dir); dent; dent = readdir(dir)) {
			char            dirname[MAX_PATHLEN];
			DIR            *dir2;
			struct dirent  *dent2;
			if ((strcmp(dent->d_name, ".") == 0)
			    || (strcmp(dent->d_name, "..") == 0))
				continue;

			snprintf(dirname, MAX_PATHLEN, "%s/%s", SYSCLASS, dent->d_name);

			dir2 = opendir(dirname);
			if (dir2) {
				for (dent2 = readdir(dir2); dent2; dent2 = readdir(dir2)) {
					char            dirname2[MAX_PATHLEN];
					DIR            *dir3;
					struct dirent  *dent3;

					if ((strcmp(dent2->d_name, ".") == 0) || (strcmp(dent2->d_name, "..") == 0))
						continue;

					snprintf(dirname2, MAX_PATHLEN, "%s/%s", dirname, dent2->d_name);

					dir3 = opendir(dirname2);
					if (dir3) {
						for (dent3 = readdir(dir3); dent3; dent3 = readdir(dir3)) {
							char
							                filename[MAX_PATHLEN];

							if (strcmp(dent3->d_name, "dev") == 0) {
								snprintf
								    (filename,
								     MAX_PATHLEN,
								     "/class/%s/%s", dent->d_name, dent2->d_name);
								setenv("DEVPATH", filename, 1);
								dbg("udev '%s', 'DEVPATH' = '%s'", dent->d_name, filename);
								execute_udev(dent->d_name, scratch, sizeof(scratch));
							}
						}
					}
				}
			}
		}
	}

	if (retval > 0)
		retval = 0;

	return -retval;
}


int main(int argc, char **argv, char **envp)
{
	init_logging("udevstart");

	setenv("ACTION", "add", 1);
	setenv("UDEV_NO_SLEEP", "1", 1);

	return udev_scan();
}
