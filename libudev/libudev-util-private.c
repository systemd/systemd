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
#include <sys/prctl.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <sys/param.h>

#include "libudev.h"
#include "libudev-private.h"

static int create_path(struct udev *udev, const char *path, bool selinux)
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
	if (stat(p, &stats) == 0) {
		if ((stats.st_mode & S_IFMT) == S_IFDIR)
			return 0;
		else
			return -ENOTDIR;
	}

	err = util_create_path(udev, p);
	if (err != 0)
		return err;

	dbg(udev, "mkdir '%s'\n", p);
	if (selinux)
		udev_selinux_setfscreatecon(udev, p, S_IFDIR|0755);
	err = mkdir(p, 0755);
	if (err != 0) {
		err = -errno;
		if (err == -EEXIST && stat(p, &stats) == 0) {
			if ((stats.st_mode & S_IFMT) == S_IFDIR)
				err = 0;
			else
				err = -ENOTDIR;
		}
	}
	if (selinux)
		udev_selinux_resetfscreatecon(udev);
	return err;
}

int util_create_path(struct udev *udev, const char *path)
{
	return create_path(udev, path, false);
}

int util_create_path_selinux(struct udev *udev, const char *path)
{
	return create_path(udev, path, true);
}

int util_delete_path(struct udev *udev, const char *path)
{
	char p[UTIL_PATH_SIZE];
	char *pos;
	int err = 0;

	if (path[0] == '/')
		while(path[1] == '/')
			path++;
	util_strscpy(p, sizeof(p), path);
	pos = strrchr(p, '/');
	if (pos == p || pos == NULL)
		return 0;

	for (;;) {
		*pos = '\0';
		pos = strrchr(p, '/');

		/* don't remove the last one */
		if ((pos == p) || (pos == NULL))
			break;

		err = rmdir(p);
		if (err < 0) {
			if (errno == ENOENT)
				err = 0;
			break;
		}
	}
	return err;
}

/* Reset permissions on the device node, before unlinking it to make sure,
 * that permissions of possible hard links will be removed too.
 */
int util_unlink_secure(struct udev *udev, const char *filename)
{
	int err;

	chown(filename, 0, 0);
	chmod(filename, 0000);
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
	size_t buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
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
	size_t buflen = sysconf(_SC_GETGR_R_SIZE_MAX);
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

static int run_program_exec(struct udev *udev, int fd_stdout, int fd_stderr,
			    char *const argv[], char **envp, const sigset_t *sigmask)
{
	int err;
	int fd;

	/* discard child output or connect to pipe */
	fd = open("/dev/null", O_RDWR);
	if (fd >= 0) {
		dup2(fd, STDIN_FILENO);
		if (fd_stdout < 0)
			dup2(fd, STDOUT_FILENO);
		if (fd_stderr < 0)
			dup2(fd, STDERR_FILENO);
		close(fd);
	} else {
		err(udev, "open /dev/null failed: %m\n");
	}

	/* connect pipes to std{out,err} */
	if (fd_stdout >= 0) {
		dup2(fd_stdout, STDOUT_FILENO);
			close(fd_stdout);
	}
	if (fd_stderr >= 0) {
		dup2(fd_stderr, STDERR_FILENO);
		close(fd_stderr);
	}

	/* terminate child in case parent goes away */
	prctl(PR_SET_PDEATHSIG, SIGTERM);

	/* restore original udev sigmask before exec */
	if (sigmask)
		sigprocmask(SIG_SETMASK, sigmask, NULL);

	execve(argv[0], argv, envp);

	/* exec failed */
	err = -errno;
	if (err == -ENOENT || err == -ENOTDIR) {
		/* may be on a filesystem which is not mounted right now */
		info(udev, "program '%s' not found\n", argv[0]);
	} else {
		/* other problems */
		err(udev, "exec of program '%s' failed\n", argv[0]);
	}
	return err;
}

static int run_program_read(struct udev *udev, int fd_stdout, int fd_stderr,
			    char *const argv[], char *result, size_t ressize, size_t *reslen)
{
	size_t respos = 0;
	int fd_ep = -1;
	struct epoll_event ep_outpipe;
	struct epoll_event ep_errpipe;
	int err = 0;

	/* read from child if requested */
	if (fd_stdout < 0 && fd_stderr < 0)
		return 0;

	fd_ep = epoll_create1(EPOLL_CLOEXEC);
	if (fd_ep < 0) {
		err = -errno;
		err(udev, "error creating epoll fd: %m\n");
		goto out;
	}

	if (fd_stdout >= 0) {
		memset(&ep_outpipe, 0, sizeof(struct epoll_event));
		ep_outpipe.events = EPOLLIN;
		ep_outpipe.data.ptr = &fd_stdout;
		if (epoll_ctl(fd_ep, EPOLL_CTL_ADD, fd_stdout, &ep_outpipe) < 0) {
			err(udev, "fail to add fd to epoll: %m\n");
			goto out;
		}
	}

	if (fd_stderr >= 0) {
		memset(&ep_errpipe, 0, sizeof(struct epoll_event));
		ep_errpipe.events = EPOLLIN;
		ep_errpipe.data.ptr = &fd_stderr;
		if (epoll_ctl(fd_ep, EPOLL_CTL_ADD, fd_stderr, &ep_errpipe) < 0) {
			err(udev, "fail to add fd to epoll: %m\n");
			goto out;
		}
	}

	/* read child output */
	while (fd_stdout >= 0 || fd_stderr >= 0) {
		int fdcount;
		struct epoll_event ev[4];
		int i;

		fdcount = epoll_wait(fd_ep, ev, ARRAY_SIZE(ev), -1);
		if (fdcount < 0) {
			if (errno == EINTR)
				continue;
			err(udev, "failed to poll: %m\n");
			err = -errno;
			goto out;
		}

		for (i = 0; i < fdcount; i++) {
			int *fd = (int *)ev[i].data.ptr;

			if (ev[i].events & EPOLLIN) {
				ssize_t count;
				char buf[4096];

				count = read(*fd, buf, sizeof(buf)-1);
				if (count <= 0)
					continue;
				buf[count] = '\0';

				/* store stdout result */
				if (result != NULL && *fd == fd_stdout) {
					if (respos + count < ressize) {
						memcpy(&result[respos], buf, count);
						respos += count;
					} else {
						err(udev, "ressize %zd too short\n", ressize);
						err = -ENOBUFS;
					}
				}

				/* log debug output only if we watch stderr */
				if (fd_stderr >= 0) {
					char *pos;
					char *line;

					pos = buf;
					while ((line = strsep(&pos, "\n"))) {
						if (pos != NULL || line[0] != '\0')
							info(udev, "'%s'(%s) '%s'\n", argv[0], *fd == fd_stdout ? "out" : "err" , line);
					}
				}
			} else if (ev[i].events & EPOLLHUP) {
				if (epoll_ctl(fd_ep, EPOLL_CTL_DEL, *fd, NULL) < 0) {
					err = -errno;
					err(udev, "failed to remove fd from epoll: %m\n");
					goto out;
				}
				*fd = -1;
			}
		}
	}

	/* return the child's stdout string */
	if (result != NULL) {
		result[respos] = '\0';
		dbg(udev, "result='%s'\n", result);
		if (reslen != NULL)
			*reslen = respos;
	}
out:
	if (fd_ep >= 0)
		close(fd_ep);
	return err;
}

int util_run_program(struct udev *udev, const char *command, char **envp,
		     char *result, size_t ressize, size_t *reslen,
		     const sigset_t *sigmask)
{
	int status;
	int outpipe[2] = {-1, -1};
	int errpipe[2] = {-1, -1};
	pid_t pid;
	char arg[UTIL_PATH_SIZE];
	char program[UTIL_PATH_SIZE];
	char *argv[((sizeof(arg) + 1) / 2) + 1];
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
				if (pos != NULL)
					while (pos[0] == ' ')
						pos++;
			} else {
				argv[i] = strsep(&pos, " ");
				if (pos != NULL)
					while (pos[0] == ' ')
						pos++;
			}
			dbg(udev, "arg[%i] '%s'\n", i, argv[i]);
			i++;
		}
		argv[i] = NULL;
	} else {
		argv[0] = arg;
		argv[1] = NULL;
	}

	/* pipes from child to parent */
	if (result != NULL || udev_get_log_priority(udev) >= LOG_INFO) {
		if (pipe2(outpipe, O_NONBLOCK) != 0) {
			err = -errno;
			err(udev, "pipe failed: %m\n");
			goto out;
		}
	}
	if (udev_get_log_priority(udev) >= LOG_INFO) {
		if (pipe2(errpipe, O_NONBLOCK) != 0) {
			err = -errno;
			err(udev, "pipe failed: %m\n");
			goto out;
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
		/* child closes parent's ends of pipes */
		if (outpipe[READ_END] >= 0) {
			close(outpipe[READ_END]);
			outpipe[READ_END] = -1;
		}
		if (errpipe[READ_END] >= 0) {
			close(errpipe[READ_END]);
			errpipe[READ_END] = -1;
		}

		err = run_program_exec(udev, outpipe[WRITE_END], errpipe[WRITE_END], argv, envp, sigmask);

		_exit(1);
	case -1:
		err(udev, "fork of '%s' failed: %m\n", argv[0]);
		err = -1;
		goto out;
	default:
		/* parent closed child's ends of pipes */
		if (outpipe[WRITE_END] >= 0) {
			close(outpipe[WRITE_END]);
			outpipe[WRITE_END] = -1;
		}
		if (errpipe[WRITE_END] >= 0) {
			close(errpipe[WRITE_END]);
			errpipe[WRITE_END] = -1;
		}

		err = run_program_read(udev, outpipe[READ_END], errpipe[READ_END], argv, result, ressize, reslen);

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

out:
	if (outpipe[READ_END] >= 0)
		close(outpipe[READ_END]);
	if (outpipe[WRITE_END] >= 0)
		close(outpipe[WRITE_END]);
	if (errpipe[READ_END] >= 0)
		close(errpipe[READ_END]);
	if (errpipe[WRITE_END] >= 0)
		close(errpipe[WRITE_END]);
	return err;
}
