/*
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
 *	51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
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

#include "udev.h"

extern char **environ;

int pass_env_to_socket(const char *sockname, const char *devpath, const char *action)
{
	int sock;
	struct sockaddr_un saddr;
	socklen_t addrlen;
	char buf[2048];
	size_t bufpos = 0;
	int i;
	ssize_t count;
	int retval = 0;

	dbg("pass environment to socket '%s'", sockname);
	sock = socket(AF_LOCAL, SOCK_DGRAM, 0);
	memset(&saddr, 0x00, sizeof(struct sockaddr_un));
	saddr.sun_family = AF_LOCAL;
	/* abstract namespace only */
	strcpy(&saddr.sun_path[1], sockname);
	addrlen = offsetof(struct sockaddr_un, sun_path) + strlen(saddr.sun_path+1) + 1;

	bufpos = snprintf(buf, sizeof(buf)-1, "%s@%s", action, devpath);
	bufpos++;
	for (i = 0; environ[i] != NULL && bufpos < sizeof(buf); i++) {
		bufpos += strlcpy(&buf[bufpos], environ[i], sizeof(buf) - bufpos-1);
		bufpos++;
	}

	count = sendto(sock, &buf, bufpos, 0, (struct sockaddr *)&saddr, addrlen);
	if (count < 0)
		retval = -1;
	info("passed %zi bytes to socket '%s', ", count, sockname);

	close(sock);
	return retval;
}

int run_program(const char *command, const char *subsystem,
		char *result, size_t ressize, size_t *reslen, int log)
{
	int retval = 0;
	int status;
	int outpipe[2] = {-1, -1};
	int errpipe[2] = {-1, -1};
	pid_t pid;
	char arg[PATH_SIZE];
	char program[PATH_SIZE];
	char *argv[(sizeof(arg) / 2) + 1];
	int devnull;
	int i;

	/* build argv from comand */
	strlcpy(arg, command, sizeof(arg));
	i = 0;
	if (strchr(arg, ' ') != NULL) {
		char *pos = arg;

		while (pos != NULL) {
			if (pos[0] == '\'') {
				/* don't separate if in apostrophes */
				pos++;
				argv[i] = strsep(&pos, "\'");
				while (pos != NULL && pos[0] == ' ')
					pos++;
			} else {
				argv[i] = strsep(&pos, " ");
			}
			dbg("arg[%i] '%s'", i, argv[i]);
			i++;
		}
		argv[i] = NULL;
	} else {
		argv[0] = arg;
		argv[1] = NULL;
	}
	info("'%s'", command);

	/* prepare pipes from child to parent */
	if (result || log) {
		if (pipe(outpipe) != 0) {
			err("pipe failed: %s", strerror(errno));
			return -1;
		}
	}
	if (log) {
		if (pipe(errpipe) != 0) {
			err("pipe failed: %s", strerror(errno));
			return -1;
		}
	}

	/* allow programs in /lib/udev called without the path */
	if (strchr(argv[0], '/') == NULL) {
		strlcpy(program, "/lib/udev/", sizeof(program));
		strlcat(program, argv[0], sizeof(program));
		argv[0] = program;
	}

	pid = fork();
	switch(pid) {
	case 0:
		/* child closes parent ends of pipes */
		if (outpipe[READ_END] > 0)
			close(outpipe[READ_END]);
		if (errpipe[READ_END] > 0)
			close(errpipe[READ_END]);

		/* discard child output or connect to pipe */
		devnull = open("/dev/null", O_RDWR);
		if (devnull > 0) {
			dup2(devnull, STDIN_FILENO);
			if (outpipe[WRITE_END] < 0)
				dup2(devnull, STDOUT_FILENO);
			if (errpipe[WRITE_END] < 0)
				dup2(devnull, STDERR_FILENO);
			close(devnull);
		} else
			err("open /dev/null failed: %s", strerror(errno));
		if (outpipe[WRITE_END] > 0) {
			dup2(outpipe[WRITE_END], STDOUT_FILENO);
			close(outpipe[WRITE_END]);
		}
		if (errpipe[WRITE_END] > 0) {
			dup2(errpipe[WRITE_END], STDERR_FILENO);
			close(errpipe[WRITE_END]);
		}
		execv(argv[0], argv);

		/* we should never reach this */
		err("exec of program '%s' failed", argv[0]);
		_exit(1);
	case -1:
		err("fork of '%s' failed: %s", argv[0], strerror(errno));
		return -1;
	default:
		/* read from child if requested */
		if (outpipe[READ_END] > 0 || errpipe[READ_END] > 0) {
			ssize_t count;
			size_t respos = 0;

			/* parent closes child ends of pipes */
			if (outpipe[WRITE_END] > 0)
				close(outpipe[WRITE_END]);
			if (errpipe[WRITE_END] > 0)
				close(errpipe[WRITE_END]);

			/* read child output */
			while (outpipe[READ_END] > 0 || errpipe[READ_END] > 0) {
				int fdcount;
				fd_set readfds;

				FD_ZERO(&readfds);
				if (outpipe[READ_END] > 0)
					FD_SET(outpipe[READ_END], &readfds);
				if (errpipe[READ_END] > 0)
					FD_SET(errpipe[READ_END], &readfds);
				fdcount = select(UDEV_MAX(outpipe[READ_END], errpipe[READ_END])+1, &readfds, NULL, NULL, NULL);
				if (fdcount < 0) {
					if (errno == EINTR)
						continue;
					retval = -1;
					break;
				}

				/* get stdout */
				if (outpipe[READ_END] > 0 && FD_ISSET(outpipe[READ_END], &readfds)) {
					char inbuf[1024];
					char *pos;
					char *line;

					count = read(outpipe[READ_END], inbuf, sizeof(inbuf)-1);
					if (count <= 0) {
						close(outpipe[READ_END]);
						outpipe[READ_END] = -1;
						if (count < 0) {
							err("stdin read failed: %s", strerror(errno));
							retval = -1;
						}
						continue;
					}
					inbuf[count] = '\0';

					/* store result for rule processing */
					if (result) {
						if (respos + count < ressize) {
							memcpy(&result[respos], inbuf, count);
							respos += count;
						} else {
							err("ressize %ld too short", (long)ressize);
							retval = -1;
						}
					}
					pos = inbuf;
					while ((line = strsep(&pos, "\n")))
						if (pos || line[0] != '\0')
							info("'%s' (stdout) '%s'", argv[0], line);
				}

				/* get stderr */
				if (errpipe[READ_END] > 0 && FD_ISSET(errpipe[READ_END], &readfds)) {
					char errbuf[1024];
					char *pos;
					char *line;

					count = read(errpipe[READ_END], errbuf, sizeof(errbuf)-1);
					if (count <= 0) {
						close(errpipe[READ_END]);
						errpipe[READ_END] = -1;
						if (count < 0)
							err("stderr read failed: %s", strerror(errno));
						continue;
					}
					errbuf[count] = '\0';
					pos = errbuf;
					while ((line = strsep(&pos, "\n")))
						if (pos || line[0] != '\0')
							info("'%s' (stderr) '%s'", argv[0], line);
				}
			}
			if (outpipe[READ_END] > 0)
				close(outpipe[READ_END]);
			if (errpipe[READ_END] > 0)
				close(errpipe[READ_END]);

			/* return the childs stdout string */
			if (result) {
				result[respos] = '\0';
				dbg("result='%s'", result);
				if (reslen)
					*reslen = respos;
			}
		}
		waitpid(pid, &status, 0);
		if (WIFEXITED(status)) {
			info("'%s' returned with status %i", argv[0], WEXITSTATUS(status));
			if (WEXITSTATUS(status) != 0)
				retval = -1;
		} else {
			err("'%s' abnormal exit", argv[0]);
			retval = -1;
		}
	}

	return retval;
}
