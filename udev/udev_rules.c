/*
 * Copyright (C) 2003 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2003-2006 Kay Sievers <kay.sievers@vrfy.org>
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

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <dirent.h>
#include <fnmatch.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "udev.h"
#include "udev_rules.h"
#include "udev_selinux.h"

extern char **environ;

/* extract possible {attr} and move str behind it */
static char *get_format_attribute(struct udev *udev, char **str)
{
	char *pos;
	char *attr = NULL;

	if (*str[0] == '{') {
		pos = strchr(*str, '}');
		if (pos == NULL) {
			err(udev, "missing closing brace for format\n");
			return NULL;
		}
		pos[0] = '\0';
		attr = *str+1;
		*str = pos+1;
		dbg(udev, "attribute='%s', str='%s'\n", attr, *str);
	}
	return attr;
}

/* extract possible format length and move str behind it*/
static int get_format_len(struct udev *udev, char **str)
{
	int num;
	char *tail;

	if (isdigit(*str[0])) {
		num = (int) strtoul(*str, &tail, 10);
		if (num > 0) {
			*str = tail;
			dbg(udev, "format length=%i\n", num);
			return num;
		} else {
			err(udev, "format parsing error '%s'\n", *str);
		}
	}
	return -1;
}

static int get_key(char **line, char **key, char **value)
{
	char *linepos;
	char *temp;

	linepos = *line;
	if (linepos == NULL)
		return -1;

	/* skip whitespace */
	while (isspace(linepos[0]))
		linepos++;

	/* get the key */
	temp = strchr(linepos, '=');
	if (temp == NULL || temp == linepos)
		return -1;
	temp[0] = '\0';
	*key = linepos;
	linepos = &temp[1];

	/* get a quoted value */
	if (linepos[0] == '"' || linepos[0] == '\'') {
		temp = strchr(&linepos[1], linepos[0]);
		if (temp != NULL) {
			temp[0] = '\0';
			*value = &linepos[1];
			goto out;
		}
	}

	/* get the value*/
	temp = strchr(linepos, '\n');
	if (temp != NULL)
		temp[0] = '\0';
	*value = linepos;
out:
	return 0;
}

static int run_program(struct udev *udev, const char *command, const char *subsystem,
		       char *result, size_t ressize, size_t *reslen)
{
	int status;
	int outpipe[2] = {-1, -1};
	int errpipe[2] = {-1, -1};
	pid_t pid;
	char arg[PATH_SIZE];
	char program[PATH_SIZE];
	char *argv[(sizeof(arg) / 2) + 1];
	int devnull;
	int i;
	int retval = 0;

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
			dbg(udev, "arg[%i] '%s'\n", i, argv[i]);
			i++;
		}
		argv[i] = NULL;
	} else {
		argv[0] = arg;
		argv[1] = NULL;
	}
	info(udev, "'%s'\n", command);

	/* prepare pipes from child to parent */
	if (result != NULL || udev_get_log_priority(udev) >= LOG_INFO) {
		if (pipe(outpipe) != 0) {
			err(udev, "pipe failed: %s\n", strerror(errno));
			return -1;
		}
	}
	if (udev_get_log_priority(udev) >= LOG_INFO) {
		if (pipe(errpipe) != 0) {
			err(udev, "pipe failed: %s\n", strerror(errno));
			return -1;
		}
	}

	/* allow programs in /lib/udev called without the path */
	if (strchr(argv[0], '/') == NULL) {
		strlcpy(program, UDEV_PREFIX "/lib/udev/", sizeof(program));
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
			err(udev, "open /dev/null failed: %s\n", strerror(errno));
		if (outpipe[WRITE_END] > 0) {
			dup2(outpipe[WRITE_END], STDOUT_FILENO);
			close(outpipe[WRITE_END]);
		}
		if (errpipe[WRITE_END] > 0) {
			dup2(errpipe[WRITE_END], STDERR_FILENO);
			close(errpipe[WRITE_END]);
		}
		execv(argv[0], argv);
		if (errno == ENOENT || errno == ENOTDIR) {
			/* may be on a filesytem which is not mounted right now */
			info(udev, "program '%s' not found\n", argv[0]);
		} else {
			/* other problems */
			err(udev, "exec of program '%s' failed\n", argv[0]);
		}
		_exit(1);
	case -1:
		err(udev, "fork of '%s' failed: %s\n", argv[0], strerror(errno));
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
							err(udev, "stdin read failed: %s\n", strerror(errno));
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
							err(udev, "ressize %ld too short\n", (long)ressize);
							retval = -1;
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
							err(udev, "stderr read failed: %s\n", strerror(errno));
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
			info(udev, "'%s' returned with status %i\n", argv[0], WEXITSTATUS(status));
			if (WEXITSTATUS(status) != 0)
				retval = -1;
		} else {
			err(udev, "'%s' abnormal exit\n", argv[0]);
			retval = -1;
		}
	}

	return retval;
}

static int import_keys_into_env(struct udevice *udevice, const char *buf, size_t bufsize)
{
	char line[LINE_SIZE];
	const char *bufline;
	char *linepos;
	char *variable;
	char *value;
	size_t cur;
	size_t count;
	int lineno;

	/* loop through the whole buffer */
	lineno = 0;
	cur = 0;
	while (cur < bufsize) {
		count = buf_get_line(buf, bufsize, cur);
		bufline = &buf[cur];
		cur += count+1;
		lineno++;

		/* eat the whitespace */
		while ((count > 0) && isspace(bufline[0])) {
			bufline++;
			count--;
		}
		if (count == 0)
			continue;

		/* see if this is a comment */
		if (bufline[0] == COMMENT_CHARACTER)
			continue;

		if (count >= sizeof(line)) {
			err(udevice->udev, "line too long, skipped\n");
			continue;
		}

		memcpy(line, bufline, count);
		line[count] = '\0';

		linepos = line;
		if (get_key(&linepos, &variable, &value) == 0) {
			dbg(udevice->udev, "import '%s=%s'\n", variable, value);

			/* handle device, renamed by external tool, returning new path */
			if (strcmp(variable, "DEVPATH") == 0) {
				info(udevice->udev, "updating devpath from '%s' to '%s'\n", udevice->dev->devpath, value);
				sysfs_device_set_values(udevice->udev, udevice->dev, value, NULL, NULL);
			} else
				name_list_key_add(udevice->udev, &udevice->env_list, variable, value);
			setenv(variable, value, 1);
		}
	}

	return 0;
}

static int import_file_into_env(struct udevice *udevice, const char *filename)
{
	char *buf;
	size_t bufsize;

	if (file_map(filename, &buf, &bufsize) != 0) {
		err(udevice->udev, "can't open '%s': %s\n", filename, strerror(errno));
		return -1;
	}
	import_keys_into_env(udevice, buf, bufsize);
	file_unmap(buf, bufsize);

	return 0;
}

static int import_program_into_env(struct udevice *udevice, const char *program)
{
	char result[2048];
	size_t reslen;

	if (run_program(udevice->udev, program, udevice->dev->subsystem, result, sizeof(result), &reslen) != 0)
		return -1;
	return import_keys_into_env(udevice, result, reslen);
}

static int import_parent_into_env(struct udevice *udevice, const char *filter)
{
	struct sysfs_device *dev_parent;
	int rc = -1;

	dev_parent = sysfs_device_get_parent(udevice->udev, udevice->dev);
	if (dev_parent != NULL) {
		struct udevice *udev_parent;
		struct name_entry *name_loop;

		dbg(udevice->udev, "found parent '%s', get the node name\n", dev_parent->devpath);
		udev_parent = udev_device_init(udevice->udev);
		if (udev_parent == NULL)
			return -1;
		/* import the udev_db of the parent */
		if (udev_db_get_device(udev_parent, dev_parent->devpath) == 0) {
			dbg(udevice->udev, "import stored parent env '%s'\n", udev_parent->name);
			list_for_each_entry(name_loop, &udev_parent->env_list, node) {
				char name[NAME_SIZE];
				char *pos;

				strlcpy(name, name_loop->name, sizeof(name));
				pos = strchr(name, '=');
				if (pos) {
					pos[0] = '\0';
					pos++;
					if (fnmatch(filter, name, 0) == 0) {
						dbg(udevice->udev, "import key '%s'\n", name_loop->name);
						name_list_add(udevice->udev, &udevice->env_list, name_loop->name, 0);
						setenv(name, pos, 1);
					} else
						dbg(udevice->udev, "skip key '%s'\n", name_loop->name);
				}
			}
			rc = 0;
		} else
			dbg(udevice->udev, "parent not found in database\n");
		udev_device_cleanup(udev_parent);
	}

	return rc;
}

static int pass_env_to_socket(struct udev *udev, const char *sockpath, const char *devpath, const char *action)
{
	int sock;
	struct sockaddr_un saddr;
	socklen_t saddrlen;
	struct stat stats;
	char buf[2048];
	size_t bufpos = 0;
	int i;
	ssize_t count;
	int retval = 0;

	dbg(udev, "pass environment to socket '%s'\n", sockpath);
	sock = socket(AF_LOCAL, SOCK_DGRAM, 0);
	memset(&saddr, 0x00, sizeof(struct sockaddr_un));
	saddr.sun_family = AF_LOCAL;
	if (sockpath[0] == '@') {
		/* abstract namespace socket requested */
		strlcpy(&saddr.sun_path[1], &sockpath[1], sizeof(saddr.sun_path)-1);
		saddrlen = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(&saddr.sun_path[1]);
	} else if (stat(sockpath, &stats) == 0 && S_ISSOCK(stats.st_mode)) {
		/* existing socket file */
		strlcpy(saddr.sun_path, sockpath, sizeof(saddr.sun_path));
		saddrlen = offsetof(struct sockaddr_un, sun_path) + strlen(saddr.sun_path);
	} else {
		/* no socket file, assume abstract namespace socket */
		strlcpy(&saddr.sun_path[1], sockpath, sizeof(saddr.sun_path)-1);
		saddrlen = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(&saddr.sun_path[1]);
	}

	bufpos = snprintf(buf, sizeof(buf), "%s@%s", action, devpath);
	bufpos++;
	for (i = 0; environ[i] != NULL && bufpos < (sizeof(buf)); i++) {
		bufpos += strlcpy(&buf[bufpos], environ[i], sizeof(buf) - bufpos);
		bufpos++;
	}
	if (bufpos > sizeof(buf))
		bufpos = sizeof(buf);

	count = sendto(sock, &buf, bufpos, 0, (struct sockaddr *)&saddr, saddrlen);
	if (count < 0)
		retval = -1;
	info(udev, "passed %zi bytes to socket '%s', \n", count, sockpath);

	close(sock);
	return retval;
}

int udev_rules_run(struct udevice *udevice)
{
	struct name_entry *name_loop;
	int retval = 0;

	dbg(udevice->udev, "executing run list\n");
	list_for_each_entry(name_loop, &udevice->run_list, node) {
		if (strncmp(name_loop->name, "socket:", strlen("socket:")) == 0) {
			pass_env_to_socket(udevice->udev, &name_loop->name[strlen("socket:")], udevice->dev->devpath, udevice->action);
		} else {
			char program[PATH_SIZE];

			strlcpy(program, name_loop->name, sizeof(program));
			udev_rules_apply_format(udevice, program, sizeof(program));
			if (run_program(udevice->udev, program, udevice->dev->subsystem, NULL, 0, NULL) != 0)
				if (!name_loop->ignore_error)
					retval = -1;
		}
	}

	return retval;
}

#define WAIT_LOOP_PER_SECOND		50
static int wait_for_file(struct udevice *udevice, const char *file, int timeout)
{
	char filepath[PATH_SIZE];
	char devicepath[PATH_SIZE] = "";
	struct stat stats;
	int loop = timeout * WAIT_LOOP_PER_SECOND;

	/* a relative path is a device attribute */
	if (file[0] != '/') {
		strlcpy(devicepath, udev_get_sys_path(udevice->udev), sizeof(devicepath));
		strlcat(devicepath, udevice->dev->devpath, sizeof(devicepath));

		strlcpy(filepath, devicepath, sizeof(filepath));
		strlcat(filepath, "/", sizeof(filepath));
		strlcat(filepath, file, sizeof(filepath));
		file = filepath;
	}

	dbg(udevice->udev, "will wait %i sec for '%s'\n", timeout, file);
	while (--loop) {
		/* lookup file */
		if (stat(file, &stats) == 0) {
			info(udevice->udev, "file '%s' appeared after %i loops\n", file, (timeout * WAIT_LOOP_PER_SECOND) - loop-1);
			return 0;
		}
		/* make sure, the device did not disappear in the meantime */
		if (devicepath[0] != '\0' && stat(devicepath, &stats) != 0) {
			info(udevice->udev, "device disappeared while waiting for '%s'\n", file);
			return -2;
		}
		info(udevice->udev, "wait for '%s' for %i mseconds\n", file, 1000 / WAIT_LOOP_PER_SECOND);
		usleep(1000 * 1000 / WAIT_LOOP_PER_SECOND);
	}
	info(udevice->udev, "waiting for '%s' failed\n", file);
	return -1;
}

/* handle "[$SUBSYSTEM/$KERNEL]<attribute>" lookup */
static int attr_get_by_subsys_id(struct udev *udev, const char *attrstr, char *devpath, size_t len, char **attr)
{
	char subsys[NAME_SIZE];
	char *pos;
	char *id;
	char *attrib;
	int found = 0;

	if (attrstr[0] != '[')
		goto out;

	attrib = strchr(&attrstr[1], ']');
	if (attrib == NULL)
		goto out;
	attrib = &attrib[1];

	strlcpy(subsys, &attrstr[1], sizeof(subsys));
	pos = strchr(subsys, ']');
	if (pos == NULL)
		goto out;
	pos[0] = '\0';
	id = strchr(subsys, '/');
	if (id == NULL)
		goto out;
	id[0] = '\0';
	id = &id[1];
	if (sysfs_lookup_devpath_by_subsys_id(udev, devpath, len, subsys, id)) {
		if (attr != NULL) {
			if (attrib[0] != '\0')
				*attr = attrib;
			else
				*attr = NULL;
		}
		found = 1;
	}
out:
	return found;
}

static int attr_subst_subdir(char *attr, size_t len)
{
	char *pos;
	int found = 0;

	pos = strstr(attr, "/*/");
	if (pos != NULL) {
		char str[PATH_SIZE];
		DIR *dir;

		pos[1] = '\0';
		strlcpy(str, &pos[2], sizeof(str));
		dir = opendir(attr);
		if (dir != NULL) {
			struct dirent *dent;

			for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
				struct stat stats;

				if (dent->d_name[0] == '.')
					continue;
				strlcat(attr, dent->d_name, len);
				strlcat(attr, str, len);
				if (stat(attr, &stats) == 0) {
					found = 1;
					break;
				}
				pos[1] = '\0';
			}
			closedir(dir);
		}
		if (!found)
			strlcat(attr, str, len);
	}

	return found;
}

void udev_rules_apply_format(struct udevice *udevice, char *string, size_t maxsize)
{
	char temp[PATH_SIZE];
	char temp2[PATH_SIZE];
	char *head, *tail, *pos, *cpos, *attr, *rest;
	int len;
	int i;
	int count;
	enum subst_type {
		SUBST_UNKNOWN,
		SUBST_DEVPATH,
		SUBST_KERNEL,
		SUBST_KERNEL_NUMBER,
		SUBST_ID,
		SUBST_DRIVER,
		SUBST_MAJOR,
		SUBST_MINOR,
		SUBST_RESULT,
		SUBST_ATTR,
		SUBST_PARENT,
		SUBST_TEMP_NODE,
		SUBST_NAME,
		SUBST_LINKS,
		SUBST_ROOT,
		SUBST_SYS,
		SUBST_ENV,
	};
	static const struct subst_map {
		char *name;
		char fmt;
		enum subst_type type;
	} map[] = {
		{ .name = "devpath",	.fmt = 'p',	.type = SUBST_DEVPATH },
		{ .name = "number",	.fmt = 'n',	.type = SUBST_KERNEL_NUMBER },
		{ .name = "kernel",	.fmt = 'k',	.type = SUBST_KERNEL },
		{ .name = "id",		.fmt = 'b',	.type = SUBST_ID },
		{ .name = "driver",	.fmt = 'd',	.type = SUBST_DRIVER },
		{ .name = "major",	.fmt = 'M',	.type = SUBST_MAJOR },
		{ .name = "minor",	.fmt = 'm',	.type = SUBST_MINOR },
		{ .name = "result",	.fmt = 'c',	.type = SUBST_RESULT },
		{ .name = "attr",	.fmt = 's',	.type = SUBST_ATTR },
		{ .name = "sysfs",	.fmt = 's',	.type = SUBST_ATTR },
		{ .name = "parent",	.fmt = 'P',	.type = SUBST_PARENT },
		{ .name = "tempnode",	.fmt = 'N',	.type = SUBST_TEMP_NODE },
		{ .name = "name",	.fmt = 'D',	.type = SUBST_NAME },
		{ .name = "links",	.fmt = 'L',	.type = SUBST_LINKS },
		{ .name = "root",	.fmt = 'r',	.type = SUBST_ROOT },
		{ .name = "sys",	.fmt = 'S',	.type = SUBST_SYS },
		{ .name = "env",	.fmt = 'E',	.type = SUBST_ENV },
		{ NULL, '\0', 0 }
	};
	enum subst_type type;
	const struct subst_map *subst;

	head = string;
	while (1) {
		len = -1;
		while (head[0] != '\0') {
			if (head[0] == '$') {
				/* substitute named variable */
				if (head[1] == '\0')
					break;
				if (head[1] == '$') {
					strlcpy(temp, head+2, sizeof(temp));
					strlcpy(head+1, temp, maxsize);
					head++;
					continue;
				}
				head[0] = '\0';
				for (subst = map; subst->name; subst++) {
					if (strncasecmp(&head[1], subst->name, strlen(subst->name)) == 0) {
						type = subst->type;
						tail = head + strlen(subst->name)+1;
						dbg(udevice->udev, "will substitute format name '%s'\n", subst->name);
						goto found;
					}
				}
				head[0] = '$';
				err(udevice->udev, "unknown format variable '%s'\n", head);
			} else if (head[0] == '%') {
				/* substitute format char */
				if (head[1] == '\0')
					break;
				if (head[1] == '%') {
					strlcpy(temp, head+2, sizeof(temp));
					strlcpy(head+1, temp, maxsize);
					head++;
					continue;
				}
				head[0] = '\0';
				tail = head+1;
				len = get_format_len(udevice->udev, &tail);
				for (subst = map; subst->name; subst++) {
					if (tail[0] == subst->fmt) {
						type = subst->type;
						tail++;
						dbg(udevice->udev, "will substitute format char '%c'\n", subst->fmt);
						goto found;
					}
				}
				head[0] = '%';
				err(udevice->udev, "unknown format char '%c'\n", tail[0]);
			}
			head++;
		}
		break;
found:
		attr = get_format_attribute(udevice->udev, &tail);
		strlcpy(temp, tail, sizeof(temp));
		dbg(udevice->udev, "format=%i, string='%s', tail='%s'\n", type ,string, tail);

		switch (type) {
		case SUBST_DEVPATH:
			strlcat(string, udevice->dev->devpath, maxsize);
			dbg(udevice->udev, "substitute devpath '%s'\n", udevice->dev->devpath);
			break;
		case SUBST_KERNEL:
			strlcat(string, udevice->dev->kernel, maxsize);
			dbg(udevice->udev, "substitute kernel name '%s'\n", udevice->dev->kernel);
			break;
		case SUBST_KERNEL_NUMBER:
			strlcat(string, udevice->dev->kernel_number, maxsize);
			dbg(udevice->udev, "substitute kernel number '%s'\n", udevice->dev->kernel_number);
			break;
		case SUBST_ID:
			if (udevice->dev_parent != NULL) {
				strlcat(string, udevice->dev_parent->kernel, maxsize);
				dbg(udevice->udev, "substitute id '%s'\n", udevice->dev_parent->kernel);
			}
			break;
		case SUBST_DRIVER:
			if (udevice->dev_parent != NULL) {
				strlcat(string, udevice->dev_parent->driver, maxsize);
				dbg(udevice->udev, "substitute driver '%s'\n", udevice->dev_parent->driver);
			}
			break;
		case SUBST_MAJOR:
			sprintf(temp2, "%d", major(udevice->devt));
			strlcat(string, temp2, maxsize);
			dbg(udevice->udev, "substitute major number '%s'\n", temp2);
			break;
		case SUBST_MINOR:
			sprintf(temp2, "%d", minor(udevice->devt));
			strlcat(string, temp2, maxsize);
			dbg(udevice->udev, "substitute minor number '%s'\n", temp2);
			break;
		case SUBST_RESULT:
			if (udevice->program_result[0] == '\0')
				break;
			/* get part part of the result string */
			i = 0;
			if (attr != NULL)
				i = strtoul(attr, &rest, 10);
			if (i > 0) {
				dbg(udevice->udev, "request part #%d of result string\n", i);
				cpos = udevice->program_result;
				while (--i) {
					while (cpos[0] != '\0' && !isspace(cpos[0]))
						cpos++;
					while (isspace(cpos[0]))
						cpos++;
				}
				if (i > 0) {
					err(udevice->udev, "requested part of result string not found\n");
					break;
				}
				strlcpy(temp2, cpos, sizeof(temp2));
				/* %{2+}c copies the whole string from the second part on */
				if (rest[0] != '+') {
					cpos = strchr(temp2, ' ');
					if (cpos)
						cpos[0] = '\0';
				}
				strlcat(string, temp2, maxsize);
				dbg(udevice->udev, "substitute part of result string '%s'\n", temp2);
			} else {
				strlcat(string, udevice->program_result, maxsize);
				dbg(udevice->udev, "substitute result string '%s'\n", udevice->program_result);
			}
			break;
		case SUBST_ATTR:
			if (attr == NULL)
				err(udevice->udev, "missing file parameter for attr\n");
			else {
				char devpath[PATH_SIZE];
				char *attrib;
				const char *value = NULL;
				size_t size;

				if (attr_get_by_subsys_id(udevice->udev, attr, devpath, sizeof(devpath), &attrib)) {
					if (attrib != NULL)
						value = sysfs_attr_get_value(udevice->udev, devpath, attrib);
					else
						break;
				}

				/* try the current device, other matches may have selected */
				if (value == NULL && udevice->dev_parent != NULL && udevice->dev_parent != udevice->dev)
					value = sysfs_attr_get_value(udevice->udev, udevice->dev_parent->devpath, attr);

				/* look at all devices along the chain of parents */
				if (value == NULL) {
					struct sysfs_device *dev_parent = udevice->dev;

					do {
						dbg(udevice->udev, "looking at '%s'\n", dev_parent->devpath);
						value = sysfs_attr_get_value(udevice->udev, dev_parent->devpath, attr);
						if (value != NULL)
							break;
						dev_parent = sysfs_device_get_parent(udevice->udev, dev_parent);
					} while (dev_parent != NULL);
				}

				if (value == NULL)
					break;

				/* strip trailing whitespace, and replace unwanted characters */
				size = strlcpy(temp2, value, sizeof(temp2));
				if (size >= sizeof(temp2))
					size = sizeof(temp2)-1;
				while (size > 0 && isspace(temp2[size-1]))
					temp2[--size] = '\0';
				count = replace_chars(temp2, ALLOWED_CHARS_INPUT);
				if (count > 0)
					info(udevice->udev, "%i character(s) replaced\n" , count);
				strlcat(string, temp2, maxsize);
				dbg(udevice->udev, "substitute sysfs value '%s'\n", temp2);
			}
			break;
		case SUBST_PARENT:
			{
				struct sysfs_device *dev_parent;

				dev_parent = sysfs_device_get_parent(udevice->udev, udevice->dev);
				if (dev_parent != NULL) {
					struct udevice *udev_parent;

					dbg(udevice->udev, "found parent '%s', get the node name\n", dev_parent->devpath);
					udev_parent = udev_device_init(udevice->udev);
					if (udev_parent != NULL) {
						/* lookup the name in the udev_db with the DEVPATH of the parent */
						if (udev_db_get_device(udev_parent, dev_parent->devpath) == 0) {
							strlcat(string, udev_parent->name, maxsize);
							dbg(udevice->udev, "substitute parent node name'%s'\n", udev_parent->name);
						} else
							dbg(udevice->udev, "parent not found in database\n");
						udev_device_cleanup(udev_parent);
					}
				}
			}
			break;
		case SUBST_TEMP_NODE:
			if (udevice->tmp_node[0] == '\0' && major(udevice->devt) > 0) {
				dbg(udevice->udev, "create temporary device node for callout\n");
				snprintf(udevice->tmp_node, sizeof(udevice->tmp_node), "%s/.tmp-%u-%u",
					 udev_get_dev_path(udevice->udev), major(udevice->devt), minor(udevice->devt));
				udevice->tmp_node[sizeof(udevice->tmp_node)-1] = '\0';
				udev_node_mknod(udevice, udevice->tmp_node, udevice->devt, 0600, 0, 0);
			}
			strlcat(string, udevice->tmp_node, maxsize);
			dbg(udevice->udev, "substitute temporary device node name '%s'\n", udevice->tmp_node);
			break;
		case SUBST_NAME:
			if (udevice->name[0] == '\0') {
				strlcat(string, udevice->dev->kernel, maxsize);
				dbg(udevice->udev, "substitute udevice->kernel '%s'\n", udevice->name);
			} else {
				strlcat(string, udevice->name, maxsize);
				dbg(udevice->udev, "substitute udevice->name '%s'\n", udevice->name);
			}
			break;
		case SUBST_LINKS:
			if (!list_empty(&udevice->symlink_list)) {
				struct name_entry *name_loop;
				char symlinks[PATH_SIZE] = "";

				list_for_each_entry(name_loop, &udevice->symlink_list, node) {
					strlcat(symlinks, name_loop->name, sizeof(symlinks));
					strlcat(symlinks, " ", sizeof(symlinks));
				}
				remove_trailing_chars(symlinks, ' ');
				strlcat(string, symlinks, maxsize);
			}
			break;
		case SUBST_ROOT:
			strlcat(string, udev_get_dev_path(udevice->udev), maxsize);
			dbg(udevice->udev, "substitute udev_root '%s'\n", udev_get_dev_path(udevice->udev));
			break;
		case SUBST_SYS:
			strlcat(string, udev_get_sys_path(udevice->udev), maxsize);
			dbg(udevice->udev, "substitute sys_path '%s'\n", udev_get_sys_path(udevice->udev));
			break;
		case SUBST_ENV:
			if (attr == NULL) {
				dbg(udevice->udev, "missing attribute\n");
				break;
			}
			pos = getenv(attr);
			if (pos == NULL) {
				dbg(udevice->udev, "env '%s' not available\n", attr);
				break;
			}
			dbg(udevice->udev, "substitute env '%s=%s'\n", attr, pos);
			strlcat(string, pos, maxsize);
			break;
		default:
			err(udevice->udev, "unknown substitution type=%i\n", type);
			break;
		}
		/* possibly truncate to format-char specified length */
		if (len >= 0 && len < (int)strlen(head)) {
			head[len] = '\0';
			dbg(udevice->udev, "truncate to %i chars, subtitution string becomes '%s'\n", len, head);
		}
		strlcat(string, temp, maxsize);
	}
}

static char *key_val(struct udev_rule *rule, struct key *key)
{
	return rule->buf + key->val_off;
}

static char *key_pair_name(struct udev_rule *rule, struct key_pair *pair)
{
	return rule->buf + pair->key_name_off;
}

static int match_key(struct udev *udev, const char *key_name, struct udev_rule *rule, struct key *key, const char *val)
{
	char value[PATH_SIZE];
	char *key_value;
	char *pos;
	int match = 0;

	if (key->operation != KEY_OP_MATCH &&
	    key->operation != KEY_OP_NOMATCH)
		return 0;

	/* look for a matching string, parts are separated by '|' */
	strlcpy(value, rule->buf + key->val_off, sizeof(value));
	key_value = value;
	dbg(udev, "key %s value='%s'\n", key_name, key_value);
	while (key_value) {
		pos = strchr(key_value, '|');
		if (pos) {
			pos[0] = '\0';
			pos++;
		}

		dbg(udev, "match %s '%s' <-> '%s'\n", key_name, key_value, val);
		match = (fnmatch(key_value, val, 0) == 0);
		if (match)
			break;

		key_value = pos;
	}

	if (match && (key->operation == KEY_OP_MATCH)) {
		dbg(udev, "%s is true (matching value)\n", key_name);
		return 0;
	}
	if (!match && (key->operation == KEY_OP_NOMATCH)) {
		dbg(udev, "%s is true (non-matching value)\n", key_name);
		return 0;
	}
	return -1;
}

/* match a single rule against a given device and possibly its parent devices */
static int match_rule(struct udevice *udevice, struct udev_rule *rule)
{
	int i;

	if (match_key(udevice->udev, "ACTION", rule, &rule->action, udevice->action))
		goto nomatch;

	if (match_key(udevice->udev, "KERNEL", rule, &rule->kernel, udevice->dev->kernel))
		goto nomatch;

	if (match_key(udevice->udev, "SUBSYSTEM", rule, &rule->subsystem, udevice->dev->subsystem))
		goto nomatch;

	if (match_key(udevice->udev, "DEVPATH", rule, &rule->devpath, udevice->dev->devpath))
		goto nomatch;

	if (match_key(udevice->udev, "DRIVER", rule, &rule->driver, udevice->dev->driver))
		goto nomatch;

	/* match NAME against a value assigned by an earlier rule */
	if (match_key(udevice->udev, "NAME", rule, &rule->name, udevice->name))
		goto nomatch;

	/* match against current list of symlinks */
	if (rule->symlink_match.operation == KEY_OP_MATCH ||
	    rule->symlink_match.operation == KEY_OP_NOMATCH) {
		struct name_entry *name_loop;
		int match = 0;

		list_for_each_entry(name_loop, &udevice->symlink_list, node) {
			if (match_key(udevice->udev, "SYMLINK", rule, &rule->symlink_match, name_loop->name) == 0) {
				match = 1;
				break;
			}
		}
		if (!match)
			goto nomatch;
	}

	for (i = 0; i < rule->env.count; i++) {
		struct key_pair *pair = &rule->env.keys[i];

		/* we only check for matches, assignments will be handled later */
		if (pair->key.operation == KEY_OP_MATCH ||
		    pair->key.operation == KEY_OP_NOMATCH) {
			const char *key_name = key_pair_name(rule, pair);
			const char *value = getenv(key_name);

			if (!value) {
				dbg(udevice->udev, "ENV{'%s'} is not set, treat as empty\n", key_name);
				value = "";
			}
			if (match_key(udevice->udev, "ENV", rule, &pair->key, value))
				goto nomatch;
		}
	}

	if (rule->test.operation == KEY_OP_MATCH ||
	    rule->test.operation == KEY_OP_NOMATCH) {
		char filename[PATH_SIZE];
		char devpath[PATH_SIZE];
		char *attr;
		struct stat statbuf;
		int match;

		strlcpy(filename, key_val(rule, &rule->test), sizeof(filename));
		udev_rules_apply_format(udevice, filename, sizeof(filename));

		if (attr_get_by_subsys_id(udevice->udev, filename, devpath, sizeof(devpath), &attr)) {
			strlcpy(filename, udev_get_sys_path(udevice->udev), sizeof(filename));
			strlcat(filename, devpath, sizeof(filename));
			if (attr != NULL) {
				strlcat(filename, "/", sizeof(filename));
				strlcat(filename, attr, sizeof(filename));
			}
		} else if (filename[0] != '/') {
			char tmp[PATH_SIZE];

			strlcpy(tmp, udev_get_sys_path(udevice->udev), sizeof(tmp));
			strlcat(tmp, udevice->dev->devpath, sizeof(tmp));
			strlcat(tmp, "/", sizeof(tmp));
			strlcat(tmp, filename, sizeof(tmp));
			strlcpy(filename, tmp, sizeof(filename));
		}

		attr_subst_subdir(filename, sizeof(filename));

		match = (stat(filename, &statbuf) == 0);
		info(udevice->udev, "'%s' %s", filename, match ? "exists\n" : "does not exist\n");
		if (match && rule->test_mode_mask > 0) {
			match = ((statbuf.st_mode & rule->test_mode_mask) > 0);
			info(udevice->udev, "'%s' has mode=%#o and %s %#o\n", filename, statbuf.st_mode,
			     match ? "matches" : "does not match",
			     rule->test_mode_mask);
		}
		if (match && rule->test.operation == KEY_OP_NOMATCH)
			goto nomatch;
		if (!match && rule->test.operation == KEY_OP_MATCH)
			goto nomatch;
		dbg(udevice->udev, "TEST key is true\n");
	}

	if (rule->wait_for.operation != KEY_OP_UNSET) {
		char filename[PATH_SIZE];
		int found;

		strlcpy(filename, key_val(rule, &rule->wait_for), sizeof(filename));
		udev_rules_apply_format(udevice, filename, sizeof(filename));
		found = (wait_for_file(udevice, filename, 10) == 0);
		if (!found && (rule->wait_for.operation != KEY_OP_NOMATCH))
			goto nomatch;
	}

	/* check for matching sysfs attribute pairs */
	for (i = 0; i < rule->attr.count; i++) {
		struct key_pair *pair = &rule->attr.keys[i];

		if (pair->key.operation == KEY_OP_MATCH ||
		    pair->key.operation == KEY_OP_NOMATCH) {
			const char *key_name = key_pair_name(rule, pair);
			const char *key_value = key_val(rule, &pair->key);
			char devpath[PATH_SIZE];
			char *attrib;
			const char *value = NULL;
			char val[VALUE_SIZE];
			size_t len;

			if (attr_get_by_subsys_id(udevice->udev, key_name, devpath, sizeof(devpath), &attrib)) {
				if (attrib != NULL)
					value = sysfs_attr_get_value(udevice->udev, devpath, attrib);
				else
					goto nomatch;
			}
			if (value == NULL)
				value = sysfs_attr_get_value(udevice->udev, udevice->dev->devpath, key_name);
			if (value == NULL)
				goto nomatch;
			strlcpy(val, value, sizeof(val));

			/* strip trailing whitespace of value, if not asked to match for it */
			len = strlen(key_value);
			if (len > 0 && !isspace(key_value[len-1])) {
				len = strlen(val);
				while (len > 0 && isspace(val[len-1]))
					val[--len] = '\0';
				dbg(udevice->udev, "removed %zi trailing whitespace chars from '%s'\n", strlen(val)-len, val);
			}

			if (match_key(udevice->udev, "ATTR", rule, &pair->key, val))
				goto nomatch;
		}
	}

	/* walk up the chain of parent devices and find a match */
	udevice->dev_parent = udevice->dev;
	while (1) {
		/* check for matching kernel device name */
		if (match_key(udevice->udev, "KERNELS", rule, &rule->kernels, udevice->dev_parent->kernel))
			goto try_parent;

		/* check for matching subsystem value */
		if (match_key(udevice->udev, "SUBSYSTEMS", rule, &rule->subsystems, udevice->dev_parent->subsystem))
			goto try_parent;

		/* check for matching driver */
		if (match_key(udevice->udev, "DRIVERS", rule, &rule->drivers, udevice->dev_parent->driver))
			goto try_parent;

		/* check for matching sysfs attribute pairs */
		for (i = 0; i < rule->attrs.count; i++) {
			struct key_pair *pair = &rule->attrs.keys[i];

			if (pair->key.operation == KEY_OP_MATCH ||
			    pair->key.operation == KEY_OP_NOMATCH) {
				const char *key_name = key_pair_name(rule, pair);
				const char *key_value = key_val(rule, &pair->key);
				const char *value;
				char val[VALUE_SIZE];
				size_t len;

				value = sysfs_attr_get_value(udevice->udev, udevice->dev_parent->devpath, key_name);
				if (value == NULL)
					value = sysfs_attr_get_value(udevice->udev, udevice->dev->devpath, key_name);
				if (value == NULL)
					goto try_parent;
				strlcpy(val, value, sizeof(val));

				/* strip trailing whitespace of value, if not asked to match for it */
				len = strlen(key_value);
				if (len > 0 && !isspace(key_value[len-1])) {
					len = strlen(val);
					while (len > 0 && isspace(val[len-1]))
						val[--len] = '\0';
					dbg(udevice->udev, "removed %zi trailing whitespace chars from '%s'\n", strlen(val)-len, val);
				}

				if (match_key(udevice->udev, "ATTRS", rule, &pair->key, val))
					goto try_parent;
			}
		}

		/* found matching device  */
		break;
try_parent:
		/* move to parent device */
		dbg(udevice->udev, "try parent sysfs device\n");
		udevice->dev_parent = sysfs_device_get_parent(udevice->udev, udevice->dev_parent);
		if (udevice->dev_parent == NULL)
			goto nomatch;
		dbg(udevice->udev, "looking at dev_parent->devpath='%s'\n", udevice->dev_parent->devpath);
		dbg(udevice->udev, "looking at dev_parent->kernel='%s'\n", udevice->dev_parent->kernel);
	}

	/* execute external program */
	if (rule->program.operation != KEY_OP_UNSET) {
		char program[PATH_SIZE];
		char result[PATH_SIZE];

		strlcpy(program, key_val(rule, &rule->program), sizeof(program));
		udev_rules_apply_format(udevice, program, sizeof(program));
		if (run_program(udevice->udev, program, udevice->dev->subsystem, result, sizeof(result), NULL) != 0) {
			dbg(udevice->udev, "PROGRAM is false\n");
			udevice->program_result[0] = '\0';
			if (rule->program.operation != KEY_OP_NOMATCH)
				goto nomatch;
		} else {
			int count;

			dbg(udevice->udev, "PROGRAM matches\n");
			remove_trailing_chars(result, '\n');
			if (rule->string_escape == ESCAPE_UNSET ||
			    rule->string_escape == ESCAPE_REPLACE) {
				count = replace_chars(result, ALLOWED_CHARS_INPUT);
				if (count > 0)
					info(udevice->udev, "%i character(s) replaced\n" , count);
			}
			dbg(udevice->udev, "result is '%s'\n", result);
			strlcpy(udevice->program_result, result, sizeof(udevice->program_result));
			dbg(udevice->udev, "PROGRAM returned successful\n");
			if (rule->program.operation == KEY_OP_NOMATCH)
				goto nomatch;
		}
		dbg(udevice->udev, "PROGRAM key is true\n");
	}

	/* check for matching result of external program */
	if (match_key(udevice->udev, "RESULT", rule, &rule->result, udevice->program_result))
		goto nomatch;

	/* import variables returned from program or or file into environment */
	if (rule->import.operation != KEY_OP_UNSET) {
		char import[PATH_SIZE];
		int rc = -1;

		strlcpy(import, key_val(rule, &rule->import), sizeof(import));
		udev_rules_apply_format(udevice, import, sizeof(import));
		dbg(udevice->udev, "check for IMPORT import='%s'\n", import);
		if (rule->import_type == IMPORT_PROGRAM) {
			rc = import_program_into_env(udevice, import);
		} else if (rule->import_type == IMPORT_FILE) {
			dbg(udevice->udev, "import file import='%s'\n", import);
			rc = import_file_into_env(udevice, import);
		} else if (rule->import_type == IMPORT_PARENT) {
			dbg(udevice->udev, "import parent import='%s'\n", import);
			rc = import_parent_into_env(udevice, import);
		}
		if (rc != 0) {
			dbg(udevice->udev, "IMPORT failed\n");
			if (rule->import.operation != KEY_OP_NOMATCH)
				goto nomatch;
		} else
			dbg(udevice->udev, "IMPORT '%s' imported\n", key_val(rule, &rule->import));
		dbg(udevice->udev, "IMPORT key is true\n");
	}

	/* rule matches, if we have ENV assignments export it */
	for (i = 0; i < rule->env.count; i++) {
		struct key_pair *pair = &rule->env.keys[i];

		if (pair->key.operation == KEY_OP_ASSIGN) {
			char temp_value[NAME_SIZE];
			const char *key_name = key_pair_name(rule, pair);
			const char *value = key_val(rule, &pair->key);

			/* make sure we don't write to the same string we possibly read from */
			strlcpy(temp_value, value, sizeof(temp_value));
			udev_rules_apply_format(udevice, temp_value, NAME_SIZE);

			if (temp_value[0] == '\0') {
				name_list_key_remove(udevice->udev, &udevice->env_list, key_name);
				unsetenv(key_name);
				info(udevice->udev, "unset ENV '%s'\n", key_name);
			} else {
				struct name_entry *entry;

				entry = name_list_key_add(udevice->udev, &udevice->env_list, key_name, temp_value);
				if (entry == NULL)
					break;
				putenv(entry->name);
				info(udevice->udev, "set ENV '%s'\n", entry->name);
			}
		}
	}

	/* if we have ATTR assignments, write value to sysfs file */
	for (i = 0; i < rule->attr.count; i++) {
		struct key_pair *pair = &rule->attr.keys[i];

		if (pair->key.operation == KEY_OP_ASSIGN) {
			const char *key_name = key_pair_name(rule, pair);
			char devpath[PATH_SIZE];
			char *attrib;
			char attr[PATH_SIZE] = "";
			char value[NAME_SIZE];
			FILE *f;

			if (attr_get_by_subsys_id(udevice->udev, key_name, devpath, sizeof(devpath), &attrib)) {
				if (attrib != NULL) {
					strlcpy(attr, udev_get_sys_path(udevice->udev), sizeof(attr));
					strlcat(attr, devpath, sizeof(attr));
					strlcat(attr, "/", sizeof(attr));
					strlcat(attr, attrib, sizeof(attr));
				}
			}

			if (attr[0] == '\0') {
				strlcpy(attr, udev_get_sys_path(udevice->udev), sizeof(attr));
				strlcat(attr, udevice->dev->devpath, sizeof(attr));
				strlcat(attr, "/", sizeof(attr));
				strlcat(attr, key_name, sizeof(attr));
			}

			attr_subst_subdir(attr, sizeof(attr));

			strlcpy(value, key_val(rule, &pair->key), sizeof(value));
			udev_rules_apply_format(udevice, value, sizeof(value));
			info(udevice->udev, "writing '%s' to sysfs file '%s'\n", value, attr);
			f = fopen(attr, "w");
			if (f != NULL) {
				if (!udevice->test_run)
					if (fprintf(f, "%s", value) <= 0)
						err(udevice->udev, "error writing ATTR{%s}: %s\n", attr, strerror(errno));
				fclose(f);
			} else
				err(udevice->udev, "error opening ATTR{%s} for writing: %s\n", attr, strerror(errno));
		}
	}
	return 0;

nomatch:
	return -1;
}

int udev_rules_get_name(struct udev_rules *rules, struct udevice *udevice)
{
	struct udev_rules_iter iter;
	struct udev_rule *rule;
	int name_set = 0;

	dbg(udevice->udev, "udevice->dev->devpath='%s'\n", udevice->dev->devpath);
	dbg(udevice->udev, "udevice->dev->kernel='%s'\n", udevice->dev->kernel);

	/* look for a matching rule to apply */
	udev_rules_iter_init(&iter, rules);
	while (1) {
		rule = udev_rules_iter_next(&iter);
		if (rule == NULL)
			break;

		if (name_set &&
		    (rule->name.operation == KEY_OP_ASSIGN ||
		     rule->name.operation == KEY_OP_ASSIGN_FINAL ||
		     rule->name.operation == KEY_OP_ADD)) {
			dbg(udevice->udev, "node name already set, rule ignored\n");
			continue;
		}

		dbg(udevice->udev, "process rule\n");
		if (match_rule(udevice, rule) == 0) {
			/* apply options */
			if (rule->ignore_device) {
				info(udevice->udev, "rule applied, '%s' is ignored\n", udevice->dev->kernel);
				udevice->ignore_device = 1;
				return 0;
			}
			if (rule->ignore_remove) {
				udevice->ignore_remove = 1;
				dbg(udevice->udev, "remove event should be ignored\n");
			}
			if (rule->link_priority != 0) {
				udevice->link_priority = rule->link_priority;
				info(udevice->udev, "link_priority=%i\n", udevice->link_priority);
			}
			if (rule->event_timeout >= 0) {
				udevice->event_timeout = rule->event_timeout;
				info(udevice->udev, "event_timeout=%i\n", udevice->event_timeout);
			}
			/* apply all_partitions option only at a main block device */
			if (rule->partitions &&
			    strcmp(udevice->dev->subsystem, "block") == 0 && udevice->dev->kernel_number[0] == '\0') {
				udevice->partitions = rule->partitions;
				dbg(udevice->udev, "creation of partition nodes requested\n");
			}

			/* apply permissions */
			if (!udevice->mode_final && rule->mode.operation != KEY_OP_UNSET) {
				if (rule->mode.operation == KEY_OP_ASSIGN_FINAL)
					udevice->mode_final = 1;
				char buf[20];
				strlcpy(buf, key_val(rule, &rule->mode), sizeof(buf));
				udev_rules_apply_format(udevice, buf, sizeof(buf));
				udevice->mode = strtol(buf, NULL, 8);
				dbg(udevice->udev, "applied mode=%#o to '%s'\n", udevice->mode, udevice->dev->kernel);
			}
			if (!udevice->owner_final && rule->owner.operation != KEY_OP_UNSET) {
				if (rule->owner.operation == KEY_OP_ASSIGN_FINAL)
					udevice->owner_final = 1;
				strlcpy(udevice->owner, key_val(rule, &rule->owner), sizeof(udevice->owner));
				udev_rules_apply_format(udevice, udevice->owner, sizeof(udevice->owner));
				dbg(udevice->udev, "applied owner='%s' to '%s'\n", udevice->owner, udevice->dev->kernel);
			}
			if (!udevice->group_final && rule->group.operation != KEY_OP_UNSET) {
				if (rule->group.operation == KEY_OP_ASSIGN_FINAL)
					udevice->group_final = 1;
				strlcpy(udevice->group, key_val(rule, &rule->group), sizeof(udevice->group));
				udev_rules_apply_format(udevice, udevice->group, sizeof(udevice->group));
				dbg(udevice->udev, "applied group='%s' to '%s'\n", udevice->group, udevice->dev->kernel);
			}

			/* collect symlinks */
			if (!udevice->symlink_final &&
			    (rule->symlink.operation == KEY_OP_ASSIGN ||
			     rule->symlink.operation == KEY_OP_ASSIGN_FINAL ||
			     rule->symlink.operation == KEY_OP_ADD)) {
				char temp[PATH_SIZE];
				char *pos, *next;
				int count;

				if (rule->symlink.operation == KEY_OP_ASSIGN_FINAL)
					udevice->symlink_final = 1;
				if (rule->symlink.operation == KEY_OP_ASSIGN ||
				    rule->symlink.operation == KEY_OP_ASSIGN_FINAL) {
					info(udevice->udev, "reset symlink list\n");
					name_list_cleanup(udevice->udev, &udevice->symlink_list);
				}
				/* allow  multiple symlinks separated by spaces */
				strlcpy(temp, key_val(rule, &rule->symlink), sizeof(temp));
				udev_rules_apply_format(udevice, temp, sizeof(temp));
				if (rule->string_escape == ESCAPE_UNSET ||
				    rule->string_escape == ESCAPE_REPLACE) {
					count = replace_chars(temp, ALLOWED_CHARS_FILE " ");
					if (count > 0)
						info(udevice->udev, "%i character(s) replaced\n" , count);
				}
				dbg(udevice->udev, "rule applied, added symlink(s) '%s'\n", temp);
				pos = temp;
				while (isspace(pos[0]))
					pos++;
				next = strchr(pos, ' ');
				while (next) {
					next[0] = '\0';
					info(udevice->udev, "add symlink '%s'\n", pos);
					name_list_add(udevice->udev, &udevice->symlink_list, pos, 0);
					while (isspace(next[1]))
						next++;
					pos = &next[1];
					next = strchr(pos, ' ');
				}
				if (pos[0] != '\0') {
					info(udevice->udev, "add symlink '%s'\n", pos);
					name_list_add(udevice->udev, &udevice->symlink_list, pos, 0);
				}
			}

			/* set name, later rules with name set will be ignored */
			if (rule->name.operation == KEY_OP_ASSIGN ||
			    rule->name.operation == KEY_OP_ASSIGN_FINAL ||
			    rule->name.operation == KEY_OP_ADD) {
				int count;

				name_set = 1;
				strlcpy(udevice->name, key_val(rule, &rule->name), sizeof(udevice->name));
				udev_rules_apply_format(udevice, udevice->name, sizeof(udevice->name));
				if (rule->string_escape == ESCAPE_UNSET ||
				    rule->string_escape == ESCAPE_REPLACE) {
					count = replace_chars(udevice->name, ALLOWED_CHARS_FILE);
					if (count > 0)
						info(udevice->udev, "%i character(s) replaced\n", count);
				}

				info(udevice->udev, "rule applied, '%s' becomes '%s'\n", udevice->dev->kernel, udevice->name);
				if (strcmp(udevice->dev->subsystem, "net") != 0)
					dbg(udevice->udev, "name, '%s' is going to have owner='%s', group='%s', mode=%#o partitions=%i\n",
					    udevice->name, udevice->owner, udevice->group, udevice->mode, udevice->partitions);
			}

			if (!udevice->run_final && rule->run.operation != KEY_OP_UNSET) {
				struct name_entry *entry;

				if (rule->run.operation == KEY_OP_ASSIGN_FINAL)
					udevice->run_final = 1;
				if (rule->run.operation == KEY_OP_ASSIGN || rule->run.operation == KEY_OP_ASSIGN_FINAL) {
					info(udevice->udev, "reset run list\n");
					name_list_cleanup(udevice->udev, &udevice->run_list);
				}
				dbg(udevice->udev, "add run '%s'\n", key_val(rule, &rule->run));
				entry = name_list_add(udevice->udev, &udevice->run_list, key_val(rule, &rule->run), 0);
				if (rule->run_ignore_error)
					entry->ignore_error = 1;
			}

			if (rule->last_rule) {
				dbg(udevice->udev, "last rule to be applied\n");
				break;
			}

			if (rule->goto_label.operation != KEY_OP_UNSET) {
				dbg(udevice->udev, "moving forward to label '%s'\n", key_val(rule, &rule->goto_label));
				udev_rules_iter_label(&iter, key_val(rule, &rule->goto_label));
			}
		}
	}

	if (!name_set) {
		info(udevice->udev, "no node name set, will use kernel name '%s'\n", udevice->dev->kernel);
		strlcpy(udevice->name, udevice->dev->kernel, sizeof(udevice->name));
	}

	if (udevice->tmp_node[0] != '\0') {
		dbg(udevice->udev, "removing temporary device node\n");
		unlink_secure(udevice->udev, udevice->tmp_node);
		udevice->tmp_node[0] = '\0';
	}

	return 0;
}

int udev_rules_get_run(struct udev_rules *rules, struct udevice *udevice)
{
	struct udev_rules_iter iter;
	struct udev_rule *rule;

	dbg(udevice->udev, "udevice->kernel='%s'\n", udevice->dev->kernel);

	/* look for a matching rule to apply */
	udev_rules_iter_init(&iter, rules);
	while (1) {
		rule = udev_rules_iter_next(&iter);
		if (rule == NULL)
			break;

		dbg(udevice->udev, "process rule\n");
		if (rule->name.operation == KEY_OP_ASSIGN ||
		    rule->name.operation == KEY_OP_ASSIGN_FINAL ||
		    rule->name.operation == KEY_OP_ADD ||
		    rule->symlink.operation == KEY_OP_ASSIGN ||
		    rule->symlink.operation == KEY_OP_ASSIGN_FINAL ||
		    rule->symlink.operation == KEY_OP_ADD ||
		    rule->mode.operation != KEY_OP_UNSET ||
		    rule->owner.operation != KEY_OP_UNSET || rule->group.operation != KEY_OP_UNSET) {
			dbg(udevice->udev, "skip rule that names a device\n");
			continue;
		}

		if (match_rule(udevice, rule) == 0) {
			if (rule->ignore_device) {
				info(udevice->udev, "rule applied, '%s' is ignored\n", udevice->dev->kernel);
				udevice->ignore_device = 1;
				return 0;
			}
			if (rule->ignore_remove) {
				udevice->ignore_remove = 1;
				dbg(udevice->udev, "remove event should be ignored\n");
			}

			if (!udevice->run_final && rule->run.operation != KEY_OP_UNSET) {
				struct name_entry *entry;

				if (rule->run.operation == KEY_OP_ASSIGN ||
				    rule->run.operation == KEY_OP_ASSIGN_FINAL) {
					info(udevice->udev, "reset run list\n");
					name_list_cleanup(udevice->udev, &udevice->run_list);
				}
				dbg(udevice->udev, "add run '%s'\n", key_val(rule, &rule->run));
				entry = name_list_add(udevice->udev, &udevice->run_list, key_val(rule, &rule->run), 0);
				if (rule->run_ignore_error)
					entry->ignore_error = 1;
				if (rule->run.operation == KEY_OP_ASSIGN_FINAL)
					break;
			}

			if (rule->last_rule) {
				dbg(udevice->udev, "last rule to be applied\n");
				break;
			}

			if (rule->goto_label.operation != KEY_OP_UNSET) {
				dbg(udevice->udev, "moving forward to label '%s'\n", key_val(rule, &rule->goto_label));
				udev_rules_iter_label(&iter, key_val(rule, &rule->goto_label));
			}
		}
	}

	return 0;
}
