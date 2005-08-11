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
#include <sys/select.h>

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

int run_program(const char *command, const char *subsystem,
		char *result, size_t ressize, size_t *reslen, int dbg)
{
	int retval = 0;
	int status;
	int outpipe[2] = {-1, -1};
	int errpipe[2] = {-1, -1};
	pid_t pid;
	char *pos;
	char arg[PATH_SIZE];
	char *argv[(sizeof(arg) / 2) + 1];
	int devnull;
	int i;

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
		argv[i] = NULL;
		dbg("execute '%s' with parsed arguments", arg);
	} else {
		argv[0] = arg;
		argv[1] = (char *) subsystem;
		argv[2] = NULL;
		dbg("execute '%s' with subsystem '%s' argument", arg, argv[1]);
	}

	/* prepare pipes from child to parent */
	if (result || dbg) {
		if (pipe(outpipe) != 0) {
			err("pipe failed");
			return -1;
		}
	}
	if (dbg) {
		if (pipe(errpipe) != 0) {
			err("pipe failed");
			return -1;
		}
	}

	pid = fork();
	switch(pid) {
	case 0:
		/* child closes parent ends of pipes */
		if (outpipe[0] > 0)
			close(outpipe[0]);
		if (errpipe[0] > 0)
			close(errpipe[0]);

		/* discard child output or connect to pipe */
		devnull = open("/dev/null", O_RDWR);
		if (devnull < 0) {
			err("open /dev/null failed");
			exit(1);
		}
		dup2(devnull, STDIN_FILENO);

		if (outpipe[1] > 0)
			dup2(outpipe[1], STDOUT_FILENO);
		else
			dup2(devnull, STDOUT_FILENO);

		if (errpipe[1] > 0)
			dup2(errpipe[1], STDERR_FILENO);
		else
			dup2(devnull, STDERR_FILENO);

		close(devnull);
		execv(arg, argv);

		/* we should never reach this */
		err("exec of program failed");
		_exit(1);
	case -1:
		err("fork of '%s' failed", arg);
		return -1;
	default:
		/* read from child if requested */
		if (outpipe[0] > 0 || errpipe[0] > 0) {
			size_t count;
			size_t respos = 0;

			/* parent closes child ends of pipes */
			if (outpipe[1] > 0)
				close(outpipe[1]);
			if (errpipe[1] > 0)
				close(errpipe[1]);

			/* read child output */
			while (outpipe[0] > 0 || errpipe[0] > 0) {
				int fdcount;
				fd_set readfds;

				FD_ZERO(&readfds);
				if (outpipe[0] > 0)
					FD_SET(outpipe[0], &readfds);
				if (errpipe[0] > 0)
					FD_SET(errpipe[0], &readfds);
				fdcount = select(UDEV_MAX(outpipe[0], errpipe[0])+1, &readfds, NULL, NULL, NULL);
				if (fdcount < 0) {
					if (errno == EINTR)
						continue;
					retval = -1;
					break;
				}

				/* get stdout */
				if (outpipe[0] > 0 && FD_ISSET(outpipe[0], &readfds)) {
					char inbuf[1024];

					count = read(outpipe[0], inbuf, sizeof(inbuf)-1);
					if (count <= 0) {
						close(outpipe[0]);
						outpipe[0] = -1;
						if (count < 0) {
							err("stdin read failed with '%s'", strerror(errno));
							retval = -1;
						}
						continue;
					}
					inbuf[count] = '\0';
					dbg("stdout: '%s'", inbuf);

					if (result) {
						if (respos + count >= ressize) {
							err("ressize %ld too short", (long)ressize);
							retval = -1;
							continue;
						}
						memcpy(&result[respos], inbuf, count);
						respos += count;
					}
				}

				/* get stderr */
				if (errpipe[0] > 0 && FD_ISSET(errpipe[0], &readfds)) {
					char errbuf[1024];

					count = read(errpipe[0], errbuf, sizeof(errbuf)-1);
					if (count <= 0) {
						close(errpipe[0]);
						errpipe[0] = -1;
						if (count < 0)
							err("stderr read failed with '%s'", strerror(errno));
						continue;
					}
					errbuf[count] = '\0';
					dbg("stderr: '%s'", errbuf);
				}
			}
			if (outpipe[0] > 0)
				close(outpipe[0]);
			if (errpipe[0] > 0)
				close(errpipe[0]);

			/* return the childs stdout string */
			if (result) {
				result[respos] = '\0';
				dbg("result='%s'", result);
				if (reslen)
					*reslen = respos;
			}
		}
		waitpid(pid, &status, 0);
		if (!WIFEXITED(status) || (WEXITSTATUS(status) != 0)) {
			dbg("exec program status 0x%x", status);
			retval = -1;
		}
	}

	return retval;
}
