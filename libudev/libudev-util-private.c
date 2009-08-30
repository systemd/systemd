/*
 * libudev - interface to udev device information
 *
 * Copyright (C) 2003-2009 Kay Sievers <kay.sievers@vrfy.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <sys/wait.h>
#include <sys/param.h>

#include "libudev.h"
#include "libudev-private.h"

int util_create_path(struct udev *udev, const char *path)
{
	char p[UTIL_PATH_SIZE];
	char *pos;
	struct stat stats;
	int err;

	util_strscpy(p, sizeof(p), path);
	pos = strrchr(p, '/');
	if (pos == NULL)
		return 0;
	while (pos != p && pos[-1] == '/')
		pos--;
	if (pos == p)
		return 0;
	pos[0] = '\0';

	dbg(udev, "stat '%s'\n", p);
	if (stat(p, &stats) == 0 && (stats.st_mode & S_IFMT) == S_IFDIR)
		return 0;

	if (util_create_path(udev, p) != 0)
		return -1;

	dbg(udev, "mkdir '%s'\n", p);
	udev_selinux_setfscreatecon(udev, p, S_IFDIR|0755);
	err = mkdir(p, 0755);
	if (err != 0 && errno == EEXIST)
		if (stat(p, &stats) == 0 && (stats.st_mode & S_IFMT) == S_IFDIR)
			err = 0;
	udev_selinux_resetfscreatecon(udev);
	return err;
}

int util_delete_path(struct udev *udev, const char *path)
{
	char p[UTIL_PATH_SIZE];
	char *pos;
	int retval;

	if (path[0] == '/')
		while(path[1] == '/')
			path++;
	util_strscpy(p, sizeof(p), path);
	pos = strrchr(p, '/');
	if (pos == p || pos == NULL)
		return 0;

	while (1) {
		*pos = '\0';
		pos = strrchr(p, '/');

		/* don't remove the last one */
		if ((pos == p) || (pos == NULL))
			break;

		/* remove if empty */
		retval = rmdir(p);
		if (errno == ENOENT)
			retval = 0;
		if (retval) {
			if (errno == ENOTEMPTY)
				return 0;
			err(udev, "rmdir(%s) failed: %m\n", p);
			break;
		}
		dbg(udev, "removed '%s'\n", p);
	}
	return 0;
}

/* Reset permissions on the device node, before unlinking it to make sure,
 * that permissions of possible hard links will be removed too.
 */
int util_unlink_secure(struct udev *udev, const char *filename)
{
	int err;

	chmod(filename, 0000);
	chown(filename, 0, 0);
	err = unlink(filename);
	if (errno == ENOENT)
		err = 0;
	if (err)
		err(udev, "unlink(%s) failed: %m\n", filename);
	return err;
}

uid_t util_lookup_user(struct udev *udev, const char *user)
{
	char *endptr;
	int buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
	char buf[buflen];
	struct passwd pwbuf;
	struct passwd *pw;
	uid_t uid;

	if (strcmp(user, "root") == 0)
		return 0;
	uid = strtoul(user, &endptr, 10);
	if (endptr[0] == '\0')
		return uid;

	errno = getpwnam_r(user, &pwbuf, buf, buflen, &pw);
	if (pw != NULL)
		return pw->pw_uid;
	if (errno == 0 || errno == ENOENT || errno == ESRCH)
		err(udev, "specified user '%s' unknown\n", user);
	else
		err(udev, "error resolving user '%s': %m\n", user);
	return 0;
}

gid_t util_lookup_group(struct udev *udev, const char *group)
{
	char *endptr;
	int buflen = sysconf(_SC_GETGR_R_SIZE_MAX);
	char *buf;
	struct group grbuf;
	struct group *gr;
	gid_t gid = 0;

	if (strcmp(group, "root") == 0)
		return 0;
	gid = strtoul(group, &endptr, 10);
	if (endptr[0] == '\0')
		return gid;
	buf = NULL;
	gid = 0;
	for (;;) {
		char *newbuf;

		newbuf = realloc(buf, buflen);
		if (!newbuf)
			break;
		buf = newbuf;
		errno = getgrnam_r(group, &grbuf, buf, buflen, &gr);
		if (gr != NULL) {
			gid = gr->gr_gid;
		} else if (errno == ERANGE) {
			buflen *= 2;
			continue;
		} else if (errno == 0 || errno == ENOENT || errno == ESRCH) {
			err(udev, "specified group '%s' unknown\n", group);
		} else {
			err(udev, "error resolving group '%s': %m\n", group);
		}
		break;
	}
	free(buf);
	return gid;
}

/* handle "[<SUBSYSTEM>/<KERNEL>]<attribute>" format */
int util_resolve_subsys_kernel(struct udev *udev, const char *string,
			       char *result, size_t maxsize, int read_value)
{
	char temp[UTIL_PATH_SIZE];
	char *subsys;
	char *sysname;
	struct udev_device *dev;
	char *attr;

	if (string[0] != '[')
		return -1;

	util_strscpy(temp, sizeof(temp), string);

	subsys = &temp[1];

	sysname = strchr(subsys, '/');
	if (sysname == NULL)
		return -1;
	sysname[0] = '\0';
	sysname = &sysname[1];

	attr = strchr(sysname, ']');
	if (attr == NULL)
		return -1;
	attr[0] = '\0';
	attr = &attr[1];
	if (attr[0] == '/')
		attr = &attr[1];
	if (attr[0] == '\0')
		attr = NULL;

	if (read_value && attr == NULL)
		return -1;

	dev = udev_device_new_from_subsystem_sysname(udev, subsys, sysname);
	if (dev == NULL)
		return -1;

	if (read_value) {
		const char *val;

		val = udev_device_get_sysattr_value(dev, attr);
		if (val != NULL)
			util_strscpy(result, maxsize, val);
		else
			result[0] = '\0';
		info(udev, "value '[%s/%s]%s' is '%s'\n", subsys, sysname, attr, result);
	} else {
		size_t l;
		char *s;

		s = result;
		l = util_strpcpyl(&s, maxsize, udev_device_get_syspath(dev), NULL);
		if (attr != NULL)
			util_strpcpyl(&s, l, "/", attr, NULL);
		info(udev, "path '[%s/%s]%s' is '%s'\n", subsys, sysname, attr, result);
	}
	udev_device_unref(dev);
	return 0;
}

int util_run_program(struct udev *udev, const char *command, char **envp,
		     char *result, size_t ressize, size_t *reslen)
{
	int status;
	int outpipe[2] = {-1, -1};
	int errpipe[2] = {-1, -1};
	pid_t pid;
	char arg[UTIL_PATH_SIZE];
	char program[UTIL_PATH_SIZE];
	char *argv[(sizeof(arg) / 2) + 1];
	int devnull;
	int i;
	int err = 0;

	info(udev, "'%s' started\n", command);

	/* build argv from command */
	util_strscpy(arg, sizeof(arg), command);
	i = 0;
	if (strchr(arg, ' ') != NULL) {
		char *pos = arg;

		while (pos != NULL && pos[0] != '\0') {
			if (pos[0] == '\'') {
				/* do not separate quotes */
				pos++;
				argv[i] = strsep(&pos, "\'");
				while (pos != NULL && pos[0] == ' ')
					pos++;
			} else {
				argv[i] = strsep(&pos, " ");
			}
			dbg(udev, "arg[%i] '%s'\n", i, argv[i]);
			i++;
		}
		argv[i] = NULL;
	} else {
		argv[0] = arg;
		argv[1] = NULL;
	}

	/* prepare pipes from child to parent */
	if (result != NULL || udev_get_log_priority(udev) >= LOG_INFO) {
		if (pipe(outpipe) != 0) {
			err(udev, "pipe failed: %m\n");
			return -1;
		}
	}
	if (udev_get_log_priority(udev) >= LOG_INFO) {
		if (pipe(errpipe) != 0) {
			err(udev, "pipe failed: %m\n");
			return -1;
		}
	}

	/* allow programs in /lib/udev/ to be called without the path */
	if (argv[0][0] != '/') {
		util_strscpyl(program, sizeof(program), LIBEXECDIR "/", argv[0], NULL);
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
			err(udev, "open /dev/null failed: %m\n");
		if (outpipe[WRITE_END] > 0) {
			dup2(outpipe[WRITE_END], STDOUT_FILENO);
			close(outpipe[WRITE_END]);
		}
		if (errpipe[WRITE_END] > 0) {
			dup2(errpipe[WRITE_END], STDERR_FILENO);
			close(errpipe[WRITE_END]);
		}
		execve(argv[0], argv, envp);
		if (errno == ENOENT || errno == ENOTDIR) {
			/* may be on a filesystem which is not mounted right now */
			info(udev, "program '%s' not found\n", argv[0]);
		} else {
			/* other problems */
			err(udev, "exec of program '%s' failed\n", argv[0]);
		}
		_exit(1);
	case -1:
		err(udev, "fork of '%s' failed: %m\n", argv[0]);
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
				fdcount = select(MAX(outpipe[READ_END], errpipe[READ_END])+1, &readfds, NULL, NULL, NULL);
				if (fdcount < 0) {
					if (errno == EINTR)
						continue;
					err = -1;
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
							err(udev, "stdin read failed: %m\n");
							err = -1;
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
							err(udev, "ressize %ld too short\n", (long)ressize);
							err = -1;
						}
					}
					pos = inbuf;
					while ((line = strsep(&pos, "\n")))
						if (pos || line[0] != '\0')
							info(udev, "'%s' (stdout) '%s'\n", argv[0], line);
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
							err(udev, "stderr read failed: %m\n");
						continue;
					}
					errbuf[count] = '\0';
					pos = errbuf;
					while ((line = strsep(&pos, "\n")))
						if (pos || line[0] != '\0')
							info(udev, "'%s' (stderr) '%s'\n", argv[0], line);
				}
			}
			if (outpipe[READ_END] > 0)
				close(outpipe[READ_END]);
			if (errpipe[READ_END] > 0)
				close(errpipe[READ_END]);

			/* return the childs stdout string */
			if (result) {
				result[respos] = '\0';
				dbg(udev, "result='%s'\n", result);
				if (reslen)
					*reslen = respos;
			}
		}
		waitpid(pid, &status, 0);
		if (WIFEXITED(status)) {
			info(udev, "'%s' returned with exitcode %i\n", command, WEXITSTATUS(status));
			if (WEXITSTATUS(status) != 0)
				err = -1;
		} else {
			err(udev, "'%s' unexpected exit with status 0x%04x\n", command, status);
			err = -1;
		}
	}
	return err;
}
