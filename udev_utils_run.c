/*
 * udev_utils_run.c - execute programs from udev and read its output
 *
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


#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>

#include "udev_libc_wrapper.h"
#include "udev.h"
#include "logging.h"
#include "udev_utils.h"
#include "list.h"


int pass_env_to_socket(const char *sockname, const char *devpath, const char *action)
{
	int sock;
	struct sockaddr_un saddr;
	socklen_t addrlen;
	char buf[2048];
	size_t bufpos = 0;
	int i;
	int retval;

	dbg("pass environment to socket '%s'", sockname);
	sock = socket(AF_LOCAL, SOCK_DGRAM, 0);
	memset(&saddr, 0x00, sizeof(struct sockaddr_un));
	saddr.sun_family = AF_LOCAL;
	/* only abstract namespace is supported */
	strcpy(&saddr.sun_path[1], sockname);
	addrlen = offsetof(struct sockaddr_un, sun_path) + strlen(saddr.sun_path+1) + 1;

	bufpos = snprintf(buf, sizeof(buf)-1, "%s@%s", action, devpath);
	bufpos++;
	for (i = 0; environ[i] != NULL && bufpos < sizeof(buf); i++) {
		bufpos += strlcpy(&buf[bufpos], environ[i], sizeof(buf) - bufpos-1);
		bufpos++;
	}

	retval = sendto(sock, &buf, bufpos, 0, (struct sockaddr *)&saddr, addrlen);
	if (retval != -1)
		retval = 0;

	close(sock);
	return retval;
}

int execute_program(const char *command, const char *subsystem,
		    char *result, size_t ressize, size_t *reslen)
{
	int retval = 0;
	int count;
	int status;
	int pipefds[2];
	pid_t pid;
	char *pos;
	char arg[PATH_SIZE];
	char *argv[(sizeof(arg) / 2) + 1];
	int devnull;
	int i;
	size_t len;

	strlcpy(arg, command, sizeof(arg));
	i = 0;
	if (strchr(arg, ' ')) {
		pos = arg;
		while (pos != NULL) {
			if (pos[0] == '\'') {
				/* don't separate if in apostrophes */
				pos++;
				argv[i] = strsep(&pos, "\'");
				while (pos && pos[0] == ' ')
					pos++;
			} else {
				argv[i] = strsep(&pos, " ");
			}
			dbg("arg[%i] '%s'", i, argv[i]);
			i++;
		}
		argv[i] =  NULL;
		dbg("execute '%s' with parsed arguments", arg);
	} else {
		argv[0] = arg;
		argv[1] = (char *) subsystem;
		argv[2] = NULL;
		dbg("execute '%s' with subsystem '%s' argument", arg, argv[1]);
	}

	if (result) {
		if (pipe(pipefds) != 0) {
			err("pipe failed");
			return -1;
		}
	}

	pid = fork();
	switch(pid) {
	case 0:
		/* child dup2 write side of pipe to STDOUT */
		devnull = open("/dev/null", O_RDWR);
		if (devnull >= 0) {
			dup2(devnull, STDIN_FILENO);
			if (!result)
				dup2(devnull, STDOUT_FILENO);
			dup2(devnull, STDERR_FILENO);
			close(devnull);
		}
		if (result)
			dup2(pipefds[1], STDOUT_FILENO);
		execv(arg, argv);
		err("exec of program failed");
		_exit(1);
	case -1:
		err("fork of '%s' failed", arg);
		return -1;
	default:
		/* parent reads from pipefds[0] */
		if (result) {
			close(pipefds[1]);
			len = 0;
			while (1) {
				count = read(pipefds[0], result + len, ressize - len-1);
				if (count < 0) {
					err("read failed with '%s'", strerror(errno));
					retval = -1;
					break;
				}

				if (count == 0)
					break;

				len += count;
				if (len >= ressize-1) {
					err("ressize %ld too short", (long)ressize);
					retval = -1;
					break;
				}
			}
			result[len] = '\0';
			close(pipefds[0]);
			if (reslen)
				*reslen = len;
		}
		waitpid(pid, &status, 0);

		if (!WIFEXITED(status) || (WEXITSTATUS(status) != 0)) {
			dbg("exec program status 0x%x", status);
			retval = -1;
		}
	}

	return retval;
}

