/*
 * Copyright (C) 2003-2010 Kay Sievers <kay.sievers@vrfy.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/poll.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/signalfd.h>
#include <linux/sockios.h>

#include "udev.h"

struct udev_event *udev_event_new(struct udev_device *dev)
{
	struct udev_event *event;

	event = calloc(1, sizeof(struct udev_event));
	if (event == NULL)
		return NULL;
	event->dev = dev;
	event->udev = udev_device_get_udev(dev);
	udev_list_init(&event->run_list);
	event->fd_signal = -1;
	event->birth_usec = now_usec();
	event->timeout_usec = 60 * 1000 * 1000;
	dbg(event->udev, "allocated event %p\n", event);
	return event;
}

void udev_event_unref(struct udev_event *event)
{
	if (event == NULL)
		return;
	udev_list_cleanup_entries(event->udev, &event->run_list);
	free(event->tmp_node);
	free(event->program_result);
	free(event->name);
	dbg(event->udev, "free event %p\n", event);
	free(event);
}

size_t udev_event_apply_format(struct udev_event *event, const char *src, char *dest, size_t size)
{
	struct udev_device *dev = event->dev;
	enum subst_type {
		SUBST_UNKNOWN,
		SUBST_TEMP_NODE,
		SUBST_ATTR,
		SUBST_ENV,
		SUBST_KERNEL,
		SUBST_KERNEL_NUMBER,
		SUBST_DRIVER,
		SUBST_DEVPATH,
		SUBST_ID,
		SUBST_MAJOR,
		SUBST_MINOR,
		SUBST_RESULT,
		SUBST_PARENT,
		SUBST_NAME,
		SUBST_LINKS,
		SUBST_ROOT,
		SUBST_SYS,
	};
	static const struct subst_map {
		char *name;
		char fmt;
		enum subst_type type;
	} map[] = {
		{ .name = "tempnode",	.fmt = 'N',	.type = SUBST_TEMP_NODE },
		{ .name = "attr",	.fmt = 's',	.type = SUBST_ATTR },
		{ .name = "sysfs",	.fmt = 's',	.type = SUBST_ATTR },
		{ .name = "env",	.fmt = 'E',	.type = SUBST_ENV },
		{ .name = "kernel",	.fmt = 'k',	.type = SUBST_KERNEL },
		{ .name = "number",	.fmt = 'n',	.type = SUBST_KERNEL_NUMBER },
		{ .name = "driver",	.fmt = 'd',	.type = SUBST_DRIVER },
		{ .name = "devpath",	.fmt = 'p',	.type = SUBST_DEVPATH },
		{ .name = "id",		.fmt = 'b',	.type = SUBST_ID },
		{ .name = "major",	.fmt = 'M',	.type = SUBST_MAJOR },
		{ .name = "minor",	.fmt = 'm',	.type = SUBST_MINOR },
		{ .name = "result",	.fmt = 'c',	.type = SUBST_RESULT },
		{ .name = "parent",	.fmt = 'P',	.type = SUBST_PARENT },
		{ .name = "name",	.fmt = 'D',	.type = SUBST_NAME },
		{ .name = "links",	.fmt = 'L',	.type = SUBST_LINKS },
		{ .name = "root",	.fmt = 'r',	.type = SUBST_ROOT },
		{ .name = "sys",	.fmt = 'S',	.type = SUBST_SYS },
	};
	const char *from;
	char *s;
	size_t l;

	from = src;
	s = dest;
	l = size;

	for (;;) {
		enum subst_type type = SUBST_UNKNOWN;
		char attrbuf[UTIL_PATH_SIZE];
		char *attr = NULL;

		while (from[0] != '\0') {
			if (from[0] == '$') {
				/* substitute named variable */
				unsigned int i;

				if (from[1] == '$') {
					from++;
					goto copy;
				}

				for (i = 0; i < ARRAY_SIZE(map); i++) {
					if (strncmp(&from[1], map[i].name, strlen(map[i].name)) == 0) {
						type = map[i].type;
						from += strlen(map[i].name)+1;
						dbg(event->udev, "will substitute format name '%s'\n", map[i].name);
						goto subst;
					}
				}
			} else if (from[0] == '%') {
				/* substitute format char */
				unsigned int i;

				if (from[1] == '%') {
					from++;
					goto copy;
				}

				for (i = 0; i < ARRAY_SIZE(map); i++) {
					if (from[1] == map[i].fmt) {
						type = map[i].type;
						from += 2;
						dbg(event->udev, "will substitute format char '%c'\n", map[i].fmt);
						goto subst;
					}
				}
			}
copy:
			/* copy char */
			if (l == 0)
				goto out;
			s[0] = from[0];
			from++;
			s++;
			l--;
		}

		goto out;
subst:
		/* extract possible $format{attr} */
		if (from[0] == '{') {
			unsigned int i;

			from++;
			for (i = 0; from[i] != '}'; i++) {
				if (from[i] == '\0') {
					err(event->udev, "missing closing brace for format '%s'\n", src);
					goto out;
				}
			}
			if (i >= sizeof(attrbuf))
				goto out;
			memcpy(attrbuf, from, i);
			attrbuf[i] = '\0';
			from += i+1;
			attr = attrbuf;
		} else {
			attr = NULL;
		}

		switch (type) {
		case SUBST_DEVPATH:
			l = util_strpcpy(&s, l, udev_device_get_devpath(dev));
			dbg(event->udev, "substitute devpath '%s'\n", udev_device_get_devpath(dev));
			break;
		case SUBST_KERNEL:
			l = util_strpcpy(&s, l, udev_device_get_sysname(dev));
			dbg(event->udev, "substitute kernel name '%s'\n", udev_device_get_sysname(dev));
			break;
		case SUBST_KERNEL_NUMBER:
			if (udev_device_get_sysnum(dev) == NULL)
				break;
			l = util_strpcpy(&s, l, udev_device_get_sysnum(dev));
			dbg(event->udev, "substitute kernel number '%s'\n", udev_device_get_sysnum(dev));
			break;
		case SUBST_ID:
			if (event->dev_parent == NULL)
				break;
			l = util_strpcpy(&s, l, udev_device_get_sysname(event->dev_parent));
			dbg(event->udev, "substitute id '%s'\n", udev_device_get_sysname(event->dev_parent));
			break;
		case SUBST_DRIVER: {
			const char *driver;

			if (event->dev_parent == NULL)
				break;

			driver = udev_device_get_driver(event->dev_parent);
			if (driver == NULL)
				break;
			l = util_strpcpy(&s, l, driver);
			dbg(event->udev, "substitute driver '%s'\n", driver);
			break;
		}
		case SUBST_MAJOR: {
			char num[UTIL_PATH_SIZE];

			sprintf(num, "%d", major(udev_device_get_devnum(dev)));
			l = util_strpcpy(&s, l, num);
			dbg(event->udev, "substitute major number '%s'\n", num);
			break;
		}
		case SUBST_MINOR: {
			char num[UTIL_PATH_SIZE];

			sprintf(num, "%d", minor(udev_device_get_devnum(dev)));
			l = util_strpcpy(&s, l, num);
			dbg(event->udev, "substitute minor number '%s'\n", num);
			break;
		}
		case SUBST_RESULT: {
			char *rest;
			int i;

			if (event->program_result == NULL)
				break;
			/* get part part of the result string */
			i = 0;
			if (attr != NULL)
				i = strtoul(attr, &rest, 10);
			if (i > 0) {
				char result[UTIL_PATH_SIZE];
				char tmp[UTIL_PATH_SIZE];
				char *cpos;

				dbg(event->udev, "request part #%d of result string\n", i);
				util_strscpy(result, sizeof(result), event->program_result);
				cpos = result;
				while (--i) {
					while (cpos[0] != '\0' && !isspace(cpos[0]))
						cpos++;
					while (isspace(cpos[0]))
						cpos++;
				}
				if (i > 0) {
					err(event->udev, "requested part of result string not found\n");
					break;
				}
				util_strscpy(tmp, sizeof(tmp), cpos);
				/* %{2+}c copies the whole string from the second part on */
				if (rest[0] != '+') {
					cpos = strchr(tmp, ' ');
					if (cpos)
						cpos[0] = '\0';
				}
				l = util_strpcpy(&s, l, tmp);
				dbg(event->udev, "substitute part of result string '%s'\n", tmp);
			} else {
				l = util_strpcpy(&s, l, event->program_result);
				dbg(event->udev, "substitute result string '%s'\n", event->program_result);
			}
			break;
		}
		case SUBST_ATTR: {
			const char *value = NULL;
			char vbuf[UTIL_NAME_SIZE];
			size_t len;
			int count;

			if (attr == NULL) {
				err(event->udev, "missing file parameter for attr\n");
				break;
			}

			/* try to read the value specified by "[dmi/id]product_name" */
			if (util_resolve_subsys_kernel(event->udev, attr, vbuf, sizeof(vbuf), 1) == 0)
				value = vbuf;

			/* try to read the attribute the device */
			if (value == NULL)
				value = udev_device_get_sysattr_value(event->dev, attr);

			/* try to read the attribute of the parent device, other matches have selected */
			if (value == NULL && event->dev_parent != NULL && event->dev_parent != event->dev)
				value = udev_device_get_sysattr_value(event->dev_parent, attr);

			if (value == NULL)
				break;

			/* strip trailing whitespace, and replace unwanted characters */
			if (value != vbuf)
				util_strscpy(vbuf, sizeof(vbuf), value);
			len = strlen(vbuf);
			while (len > 0 && isspace(vbuf[--len]))
				vbuf[len] = '\0';
			count = udev_util_replace_chars(vbuf, UDEV_ALLOWED_CHARS_INPUT);
			if (count > 0)
				info(event->udev, "%i character(s) replaced\n" , count);
			l = util_strpcpy(&s, l, vbuf);
			dbg(event->udev, "substitute sysfs value '%s'\n", vbuf);
			break;
		}
		case SUBST_PARENT: {
			struct udev_device *dev_parent;
			const char *devnode;

			dev_parent = udev_device_get_parent(event->dev);
			if (dev_parent == NULL)
				break;
				devnode = udev_device_get_devnode(dev_parent);
			if (devnode != NULL) {
				size_t devlen = strlen(udev_get_dev_path(event->udev))+1;

				l = util_strpcpy(&s, l, &devnode[devlen]);
				dbg(event->udev, "found parent '%s', got node name '%s'\n",
				    udev_device_get_syspath(dev_parent), &devnode[devlen]);
			}
			break;
		}
		case SUBST_TEMP_NODE: {
			dev_t devnum;
			struct stat statbuf;
			char filename[UTIL_PATH_SIZE];
			const char *devtype;

			if (event->tmp_node != NULL) {
				l = util_strpcpy(&s, l, event->tmp_node);
				dbg(event->udev, "tempnode: return earlier created one\n");
				break;
			}
			devnum = udev_device_get_devnum(dev);
			if (major(devnum) == 0)
				break;
			/* lookup kernel provided node */
			if (udev_device_get_knodename(dev) != NULL) {
				util_strscpyl(filename, sizeof(filename),
					      udev_get_dev_path(event->udev), "/", udev_device_get_knodename(dev), NULL);
				if (stat(filename, &statbuf) == 0 && statbuf.st_rdev == devnum) {
					l = util_strpcpy(&s, l, filename);
					dbg(event->udev, "tempnode: return kernel node\n");
					break;
				}
			}
			/* lookup /dev/{char,block}/<maj>:<min> */
			if (strcmp(udev_device_get_subsystem(dev), "block") == 0)
				devtype = "block";
			else
				devtype = "char";
			snprintf(filename, sizeof(filename), "%s/%s/%u:%u",
				 udev_get_dev_path(event->udev), devtype,
				 major(udev_device_get_devnum(dev)),
				 minor(udev_device_get_devnum(dev)));
			if (stat(filename, &statbuf) == 0 && statbuf.st_rdev == devnum) {
				l = util_strpcpy(&s, l, filename);
				dbg(event->udev, "tempnode: return maj:min node\n");
				break;
			}
			/* create temporary node */
			dbg(event->udev, "tempnode: create temp node\n");
			asprintf(&event->tmp_node, "%s/.tmp-%s-%u:%u",
				 udev_get_dev_path(event->udev), devtype,
				 major(udev_device_get_devnum(dev)),
				 minor(udev_device_get_devnum(dev)));
			if (event->tmp_node == NULL)
				break;
			udev_node_mknod(dev, event->tmp_node, 0600, 0, 0);
			l = util_strpcpy(&s, l, event->tmp_node);
			break;
		}
		case SUBST_NAME:
			if (event->name != NULL) {
				l = util_strpcpy(&s, l, event->name);
				dbg(event->udev, "substitute name '%s'\n", event->name);
			} else {
				l = util_strpcpy(&s, l, udev_device_get_sysname(dev));
				dbg(event->udev, "substitute sysname '%s'\n", udev_device_get_sysname(dev));
			}
			break;
		case SUBST_LINKS: {
			size_t devlen = strlen(udev_get_dev_path(event->udev))+1;
			struct udev_list_entry *list_entry;

			list_entry = udev_device_get_devlinks_list_entry(dev);
			if (list_entry == NULL)
				break;
			l = util_strpcpy(&s, l, &udev_list_entry_get_name(list_entry)[devlen]);
			udev_list_entry_foreach(list_entry, udev_list_entry_get_next(list_entry))
				l = util_strpcpyl(&s, l, " ", &udev_list_entry_get_name(list_entry)[devlen], NULL);
			break;
		}
		case SUBST_ROOT:
			l = util_strpcpy(&s, l, udev_get_dev_path(event->udev));
			dbg(event->udev, "substitute udev_root '%s'\n", udev_get_dev_path(event->udev));
			break;
		case SUBST_SYS:
			l = util_strpcpy(&s, l, udev_get_sys_path(event->udev));
			dbg(event->udev, "substitute sys_path '%s'\n", udev_get_sys_path(event->udev));
			break;
		case SUBST_ENV:
			if (attr == NULL) {
				dbg(event->udev, "missing attribute\n");
				break;
			} else {
				const char *value;

				value = udev_device_get_property_value(event->dev, attr);
				if (value == NULL)
					break;
				dbg(event->udev, "substitute env '%s=%s'\n", attr, value);
				l = util_strpcpy(&s, l, value);
				break;
			}
		default:
			err(event->udev, "unknown substitution type=%i\n", type);
			break;
		}
	}

out:
	s[0] = '\0';
	dbg(event->udev, "'%s' -> '%s' (%zu)\n", src, dest, l);
	return l;
}

static int spawn_exec(struct udev_event *event,
		      const char *cmd, char *const argv[], char **envp, const sigset_t *sigmask,
		      int fd_stdout, int fd_stderr)
{
	struct udev *udev = event->udev;
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
	err(udev, "failed to execute '%s' '%s': %m\n", argv[0], cmd);
	return err;
}

static int spawn_read(struct udev_event *event,
		      const char *cmd,
		      int fd_stdout, int fd_stderr,
		      char *result, size_t ressize)
{
	struct udev *udev = event->udev;
	size_t respos = 0;
	int fd_ep = -1;
	struct epoll_event ep_outpipe, ep_errpipe;
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
		int timeout;
		int fdcount;
		struct epoll_event ev[4];
		int i;

		if (event->timeout_usec > 0) {
			unsigned long long age_usec;

			age_usec = now_usec() - event->birth_usec;
			if (age_usec >= event->timeout_usec) {
				err = -ETIMEDOUT;
				err(udev, "timeout '%s'\n", cmd);
				goto out;
			}
			timeout = ((event->timeout_usec - age_usec) / 1000) + 1000;
		} else {
			timeout = -1;
		}

		fdcount = epoll_wait(fd_ep, ev, ARRAY_SIZE(ev), timeout);
		if (fdcount < 0) {
			if (errno == EINTR)
				continue;
			err = -errno;
			err(udev, "failed to poll: %m\n");
			goto out;
		}
		if (fdcount == 0) {
			err  = -ETIMEDOUT;
			err(udev, "timeout '%s'\n", cmd);
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
						err(udev, "'%s' ressize %zd too short\n", cmd, ressize);
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
							info(udev, "'%s'(%s) '%s'\n", cmd, *fd == fd_stdout ? "out" : "err" , line);
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
	}
out:
	if (fd_ep >= 0)
		close(fd_ep);
	return err;
}

static int spawn_wait(struct udev_event *event, const char *cmd, pid_t pid)
{
	struct udev *udev = event->udev;
	struct pollfd pfd[1];
	int err = 0;

	pfd[0].events = POLLIN;
	pfd[0].fd = event->fd_signal;

	while (pid > 0) {
		int timeout;
		int fdcount;

		if (event->timeout_usec > 0) {
			unsigned long long age_usec;

			age_usec = now_usec() - event->birth_usec;
			if (age_usec >= event->timeout_usec)
				timeout = 1000;
			else
				timeout = ((event->timeout_usec - age_usec) / 1000) + 1000;
		} else {
			timeout = -1;
		}

		fdcount = poll(pfd, 1, timeout);
		if (fdcount < 0) {
			if (errno == EINTR)
				continue;
			err = -errno;
			err(udev, "failed to poll: %m\n");
			goto out;
		}
		if (fdcount == 0) {
			err(udev, "timeout: killing '%s' [%u]\n", cmd, pid);
			kill(pid, SIGKILL);
		}

		if (pfd[0].revents & POLLIN) {
			struct signalfd_siginfo fdsi;
			int status;
			ssize_t size;

			size = read(event->fd_signal, &fdsi, sizeof(struct signalfd_siginfo));
			if (size != sizeof(struct signalfd_siginfo))
				continue;

			switch (fdsi.ssi_signo) {
			case SIGTERM:
				event->sigterm = true;
				break;
			case SIGCHLD:
				if (waitpid(pid, &status, WNOHANG) < 0)
					break;
				if (WIFEXITED(status)) {
					info(udev, "'%s' [%u] exit with return code %i\n", cmd, pid, WEXITSTATUS(status));
					if (WEXITSTATUS(status) != 0)
						err = -1;
				} else if (WIFSIGNALED(status)) {
					err(udev, "'%s' [%u] terminated by signal %i (%s)\n", cmd, pid, WTERMSIG(status), strsignal(WTERMSIG(status)));
					err = -1;
				} else if (WIFSTOPPED(status)) {
					err(udev, "'%s' [%u] stopped\n", cmd, pid);
					err = -1;
				} else if (WIFCONTINUED(status)) {
					err(udev, "'%s' [%u] continued\n", cmd, pid);
					err = -1;
				} else {
					err(udev, "'%s' [%u] exit with status 0x%04x\n", cmd, pid, status);
					err = -1;
				}
				pid = 0;
				break;
			}
		}
	}
out:
	return err;
}

int udev_event_spawn(struct udev_event *event,
		     const char *cmd, char **envp, const sigset_t *sigmask,
		     char *result, size_t ressize)
{
	struct udev *udev = event->udev;
	int outpipe[2] = {-1, -1};
	int errpipe[2] = {-1, -1};
	pid_t pid;
	char arg[UTIL_PATH_SIZE];
	char program[UTIL_PATH_SIZE];
	char *argv[((sizeof(arg) + 1) / 2) + 1];
	int i;
	int err = 0;

	/* build argv from command */
	util_strscpy(arg, sizeof(arg), cmd);
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

		info(udev, "starting '%s'\n", cmd);

		err = spawn_exec(event, cmd, argv, envp, sigmask,
				 outpipe[WRITE_END], errpipe[WRITE_END]);

		_exit(2 );
	case -1:
		err(udev, "fork of '%s' failed: %m\n", cmd);
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

		err = spawn_read(event, cmd,
				 outpipe[READ_END], errpipe[READ_END],
				 result, ressize);

		err = spawn_wait(event, cmd, pid);
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

static void rename_netif_kernel_log(struct ifreq ifr)
{
	int klog;
	FILE *f;

	klog = open("/dev/kmsg", O_WRONLY);
	if (klog < 0)
		return;

	f = fdopen(klog, "w");
	if (f == NULL) {
		close(klog);
		return;
	}

	fprintf(f, "<30>udevd[%u]: renamed network interface %s to %s\n",
		getpid(), ifr.ifr_name, ifr.ifr_newname);
	fclose(f);
}

static int rename_netif(struct udev_event *event)
{
	struct udev_device *dev = event->dev;
	int sk;
	struct ifreq ifr;
	int loop;
	int err;

	info(event->udev, "changing net interface name from '%s' to '%s'\n",
	     udev_device_get_sysname(dev), event->name);

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0) {
		err = -errno;
		err(event->udev, "error opening socket: %m\n");
		return err;
	}

	memset(&ifr, 0x00, sizeof(struct ifreq));
	util_strscpy(ifr.ifr_name, IFNAMSIZ, udev_device_get_sysname(dev));
	util_strscpy(ifr.ifr_newname, IFNAMSIZ, event->name);
	err = ioctl(sk, SIOCSIFNAME, &ifr);
	if (err == 0) {
		rename_netif_kernel_log(ifr);
		goto out;
	}

	/* keep trying if the destination interface name already exists */
	err = -errno;
	if (err != -EEXIST)
		goto out;

	/* free our own name, another process may wait for us */
	snprintf(ifr.ifr_newname, IFNAMSIZ, "rename%u", udev_device_get_ifindex(dev));
	err = ioctl(sk, SIOCSIFNAME, &ifr);
	if (err < 0) {
		err = -errno;
		goto out;
	}

	/* log temporary name */
	rename_netif_kernel_log(ifr);

	/* wait a maximum of 90 seconds for our target to become available */
	util_strscpy(ifr.ifr_name, IFNAMSIZ, ifr.ifr_newname);
	util_strscpy(ifr.ifr_newname, IFNAMSIZ, event->name);
	loop = 90 * 20;
	while (loop--) {
		const struct timespec duration = { 0, 1000 * 1000 * 1000 / 20 };

		dbg(event->udev, "wait for netif '%s' to become free, loop=%i\n",
		    event->name, (90 * 20) - loop);
		nanosleep(&duration, NULL);

		err = ioctl(sk, SIOCSIFNAME, &ifr);
		if (err == 0) {
			rename_netif_kernel_log(ifr);
			break;
		}
		err = -errno;
		if (err != -EEXIST)
			break;
	}

out:
	if (err < 0)
		err(event->udev, "error changing net interface name %s to %s: %m\n", ifr.ifr_name, ifr.ifr_newname);
	close(sk);
	return err;
}

int udev_event_execute_rules(struct udev_event *event, struct udev_rules *rules, const sigset_t *sigmask)
{
	struct udev_device *dev = event->dev;
	int err = 0;

	if (udev_device_get_subsystem(dev) == NULL)
		return -1;

	if (strcmp(udev_device_get_action(dev), "remove") == 0) {
		udev_device_read_db(dev, NULL);
		udev_device_delete_db(dev);
		udev_device_tag_index(dev, NULL, false);

		if (major(udev_device_get_devnum(dev)) != 0)
			udev_watch_end(event->udev, dev);

		udev_rules_apply_to_event(rules, event, sigmask);

		if (major(udev_device_get_devnum(dev)) != 0)
			err = udev_node_remove(dev);
	} else {
		event->dev_db = udev_device_new_from_syspath(event->udev, udev_device_get_syspath(dev));
		if (event->dev_db != NULL) {
			udev_device_read_db(event->dev_db, NULL);
			udev_device_set_info_loaded(event->dev_db);

			/* disable watch during event processing */
			if (major(udev_device_get_devnum(dev)) != 0)
				udev_watch_end(event->udev, event->dev_db);
		}

		udev_rules_apply_to_event(rules, event, sigmask);

		/* rename a new network interface, if needed */
		if (udev_device_get_ifindex(dev) > 0 && strcmp(udev_device_get_action(dev), "add") == 0 &&
		    event->name != NULL && strcmp(event->name, udev_device_get_sysname(dev)) != 0) {
			char syspath[UTIL_PATH_SIZE];
			char *pos;

			err = rename_netif(event);
			if (err == 0) {
				info(event->udev, "renamed netif to '%s'\n", event->name);

				/* remember old name */
				udev_device_add_property(dev, "INTERFACE_OLD", udev_device_get_sysname(dev));

				/* now change the devpath, because the kernel device name has changed */
				util_strscpy(syspath, sizeof(syspath), udev_device_get_syspath(dev));
				pos = strrchr(syspath, '/');
				if (pos != NULL) {
					pos++;
					util_strscpy(pos, sizeof(syspath) - (pos - syspath), event->name);
					udev_device_set_syspath(event->dev, syspath);
					udev_device_add_property(dev, "INTERFACE", udev_device_get_sysname(dev));
					info(event->udev, "changed devpath to '%s'\n", udev_device_get_devpath(dev));
				}
			}
		}

		if (major(udev_device_get_devnum(dev)) != 0) {
			char filename[UTIL_PATH_SIZE];

			if (event->tmp_node != NULL) {
				info(event->udev, "cleanup temporary device node\n");
				util_unlink_secure(event->udev, event->tmp_node);
				free(event->tmp_node);
				event->tmp_node = NULL;
			}

			/* no rule, use kernel provided name */
			if (event->name == NULL) {
				if (udev_device_get_knodename(dev) != NULL) {
					event->name = strdup(udev_device_get_knodename(dev));
					info(event->udev, "no node name set, will use kernel supplied name '%s'\n", event->name);
				} else {
					event->name = strdup(udev_device_get_sysname(event->dev));
					info(event->udev, "no node name set, will use device name '%s'\n", event->name);
				}
			}

			if (event->name == NULL || event->name[0] == '\0') {
				udev_device_delete_db(dev);
				udev_device_tag_index(dev, NULL, false);
				udev_device_unref(event->dev_db);
				err = -ENOMEM;
				err(event->udev, "no node name, something went wrong, ignoring\n");
				goto out;
			}

			if (udev_device_get_knodename(dev) != NULL && strcmp(udev_device_get_knodename(dev), event->name) != 0)
				err(event->udev, "kernel-provided name '%s' and NAME= '%s' disagree, "
				    "please use SYMLINK+= or change the kernel to provide the proper name\n",
				    udev_device_get_knodename(dev), event->name);

			/* set device node name */
			util_strscpyl(filename, sizeof(filename), udev_get_dev_path(event->udev), "/", event->name, NULL);
			udev_device_set_devnode(dev, filename);

			/* remove/update possible left-over symlinks from old database entry */
			if (event->dev_db != NULL)
				udev_node_update_old_links(dev, event->dev_db);

			if (!event->mode_set) {
				if (udev_device_get_devnode_mode(dev) > 0) {
					/* kernel supplied value */
					event->mode = udev_device_get_devnode_mode(dev);
				} else if (event->gid > 0) {
					/* default 0660 if a group is assigned */
					event->mode = 0660;
				} else {
					/* default 0600 */
					event->mode = 0600;
				}
			}

			err = udev_node_add(dev, event->mode, event->uid, event->gid);
		}

		/* preserve old, or get new initialization timestamp */
		if (event->dev_db != NULL && udev_device_get_usec_initialized(event->dev_db) > 0)
			udev_device_set_usec_initialized(event->dev, udev_device_get_usec_initialized(event->dev_db));
		else
			udev_device_set_usec_initialized(event->dev, now_usec());

		/* (re)write database file */
		udev_device_update_db(dev);
		udev_device_tag_index(dev, event->dev_db, true);
		udev_device_set_is_initialized(dev);

		udev_device_unref(event->dev_db);
		event->dev_db = NULL;
	}
out:
	return err;
}

int udev_event_execute_run(struct udev_event *event, const sigset_t *sigmask)
{
	struct udev_list_entry *list_entry;
	int err = 0;

	dbg(event->udev, "executing run list\n");
	udev_list_entry_foreach(list_entry, udev_list_get_entry(&event->run_list)) {
		const char *cmd = udev_list_entry_get_name(list_entry);

		if (strncmp(cmd, "socket:", strlen("socket:")) == 0) {
			struct udev_monitor *monitor;

			monitor = udev_monitor_new_from_socket(event->udev, &cmd[strlen("socket:")]);
			if (monitor == NULL)
				continue;
			udev_monitor_send_device(monitor, NULL, event->dev);
			udev_monitor_unref(monitor);
		} else {
			char program[UTIL_PATH_SIZE];
			char **envp;

			if (event->exec_delay > 0) {
				info(event->udev, "delay execution of '%s'\n", program);
				sleep(event->exec_delay);
			}

			udev_event_apply_format(event, cmd, program, sizeof(program));
			envp = udev_device_get_properties_envp(event->dev);
			if (udev_event_spawn(event, program, envp, sigmask, NULL, 0) < 0) {
				if (udev_list_entry_get_num(list_entry))
					err = -1;
			}
		}
	}
	return err;
}
