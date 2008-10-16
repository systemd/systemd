/*
 * Copyright (C) 2003 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2003-2008 Kay Sievers <kay.sievers@vrfy.org>
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
#include "udev-rules.h"

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

static int run_program(struct udev_device *dev, const char *command,
		       char *result, size_t ressize, size_t *reslen)
{
	struct udev *udev = udev_device_get_udev(dev);
	int status;
	char **envp;
	int outpipe[2] = {-1, -1};
	int errpipe[2] = {-1, -1};
	pid_t pid;
	char arg[UTIL_PATH_SIZE];
	char program[UTIL_PATH_SIZE];
	char *argv[(sizeof(arg) / 2) + 1];
	int devnull;
	int i;
	int err = 0;

	/* build argv from command */
	util_strlcpy(arg, command, sizeof(arg));
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
	info(udev, "'%s'\n", command);

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
	if (strchr(argv[0], '/') == NULL) {
		util_strlcpy(program, UDEV_PREFIX "/lib/udev/", sizeof(program));
		util_strlcat(program, argv[0], sizeof(program));
		argv[0] = program;
	}

	envp = udev_device_get_properties_envp(dev);

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
			/* may be on a filesytem which is not mounted right now */
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
				fdcount = select(UDEV_MAX(outpipe[READ_END], errpipe[READ_END])+1, &readfds, NULL, NULL, NULL);
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
			info(udev, "'%s' returned with status %i\n", argv[0], WEXITSTATUS(status));
			if (WEXITSTATUS(status) != 0)
				err = -1;
		} else {
			err(udev, "'%s' abnormal exit\n", argv[0]);
			err = -1;
		}
	}

	return err;
}

static int import_property_from_string(struct udev_device *dev, char *line)
{
	struct udev *udev = udev_device_get_udev(dev);
	char *key;
	char *val;
	size_t len;

	/* find key */
	key = line;
	while (isspace(key[0]))
		key++;

	/* comment or empty line */
	if (key[0] == '#' || key[0] == '\0')
		return -1;

	/* split key/value */
	val = strchr(key, '=');
	if (val == NULL)
		return -1;
	val[0] = '\0';
	val++;

	/* find value */
	while (isspace(val[0]))
		val++;

	/* terminate key */
	len = strlen(key);
	if (len == 0)
		return -1;
	while (isspace(key[len-1]))
		len--;
	key[len] = '\0';

	/* terminate value */
	len = strlen(val);
	if (len == 0)
		return -1;
	while (isspace(val[len-1]))
		len--;
	val[len] = '\0';

	if (len == 0)
		return -1;

	/* unquote */
	if (val[0] == '"' || val[0] == '\'') {
		if (val[len-1] != val[0]) {
			info(udev, "inconsistent quoting: '%s', skip\n", line);
			return -1;
		}
		val[len-1] = '\0';
		val++;
	}

	info(udev, "adding '%s'='%s'\n", key, val);

	/* handle device, renamed by external tool, returning new path */
	if (strcmp(key, "DEVPATH") == 0) {
		char syspath[UTIL_PATH_SIZE];

		info(udev, "updating devpath from '%s' to '%s'\n",
		     udev_device_get_devpath(dev), val);
		util_strlcpy(syspath, udev_get_sys_path(udev), sizeof(syspath));
		util_strlcat(syspath, val, sizeof(syspath));
		udev_device_set_syspath(dev, syspath);
	} else {
		struct udev_list_entry *entry;

		entry = udev_device_add_property(dev, key, val);
		/* store in db */
		udev_list_entry_set_flag(entry, 1);
	}
	return 0;
}

static int import_file_into_env(struct udev_device *dev, const char *filename)
{
	FILE *f;
	char line[UTIL_LINE_SIZE];

	f = fopen(filename, "r");
	if (f == NULL)
		return -1;
	while (fgets(line, sizeof(line), f))
		import_property_from_string(dev, line);
	fclose(f);
	return 0;
}

static int import_program_into_env(struct udev_device *dev, const char *program)
{
	char result[2048];
	size_t reslen;
	char *line;

	if (run_program(dev, program, result, sizeof(result), &reslen) != 0)
		return -1;

	line = result;
	while (line != NULL) {
		char *pos;

		pos = strchr(line, '\n');
		if (pos != NULL) {
			pos[0] = '\0';
			pos = &pos[1];
		}
		import_property_from_string(dev, line);
		line = pos;
	}
	return 0;
}

static int import_parent_into_env(struct udev_device *dev, const char *filter)
{
	struct udev *udev = udev_device_get_udev(dev);
	struct udev_device *dev_parent;
	struct udev_list_entry *list_entry;

	dev_parent = udev_device_get_parent(dev);
	if (dev_parent == NULL)
		return -1;

	dbg(udev, "found parent '%s', get the node name\n", udev_device_get_syspath(dev_parent));
	udev_list_entry_foreach(list_entry, udev_device_get_properties_list_entry(dev_parent)) {
		const char *key = udev_list_entry_get_name(list_entry);
		const char *val = udev_list_entry_get_value(list_entry);

		if (fnmatch(filter, key, 0) == 0) {
			struct udev_list_entry *entry;

			dbg(udev, "import key '%s=%s'\n", key, val);
			entry = udev_device_add_property(dev, key, val);
			/* store in db */
			udev_list_entry_set_flag(entry, 1);
		}
	}
	return 0;
}

int udev_rules_run(struct udev_event *event)
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
			udev_monitor_send_device(monitor, event->dev);
			udev_monitor_unref(monitor);
		} else {
			char program[UTIL_PATH_SIZE];

			util_strlcpy(program, cmd, sizeof(program));
			udev_rules_apply_format(event, program, sizeof(program));
			if (run_program(event->dev, program, NULL, 0, NULL) != 0) {
				if (!udev_list_entry_get_flag(list_entry))
					err = -1;
			}
		}
	}
	return err;
}

#define WAIT_LOOP_PER_SECOND		50
static int wait_for_file(struct udev_event *event, const char *file, int timeout)
{
	char filepath[UTIL_PATH_SIZE];
	char devicepath[UTIL_PATH_SIZE] = "";
	struct stat stats;
	int loop = timeout * WAIT_LOOP_PER_SECOND;

	/* a relative path is a device attribute */
	if (file[0] != '/') {
		util_strlcpy(devicepath, udev_get_sys_path(event->udev), sizeof(devicepath));
		util_strlcat(devicepath, udev_device_get_devpath(event->dev), sizeof(devicepath));

		util_strlcpy(filepath, devicepath, sizeof(filepath));
		util_strlcat(filepath, "/", sizeof(filepath));
		util_strlcat(filepath, file, sizeof(filepath));
		file = filepath;
	}

	dbg(event->udev, "will wait %i sec for '%s'\n", timeout, file);
	while (--loop) {
		/* lookup file */
		if (stat(file, &stats) == 0) {
			info(event->udev, "file '%s' appeared after %i loops\n", file, (timeout * WAIT_LOOP_PER_SECOND) - loop-1);
			return 0;
		}
		/* make sure, the device did not disappear in the meantime */
		if (devicepath[0] != '\0' && stat(devicepath, &stats) != 0) {
			info(event->udev, "device disappeared while waiting for '%s'\n", file);
			return -2;
		}
		info(event->udev, "wait for '%s' for %i mseconds\n", file, 1000 / WAIT_LOOP_PER_SECOND);
		usleep(1000 * 1000 / WAIT_LOOP_PER_SECOND);
	}
	info(event->udev, "waiting for '%s' failed\n", file);
	return -1;
}

/* handle "[$SUBSYSTEM/$KERNEL]<attribute>" lookup */
static int split_subsys_sysname(struct udev *udev, char *attrstr, char **subsys, char **sysname, char **attr)
{
	char *pos;

	if (attrstr[0] != '[')
		return -1;

	*subsys = &attrstr[1];
	pos = strchr(*subsys, ']');
	if (pos == NULL)
		return -1;
	pos[0] = '\0';
	pos = &pos[1];

	if (pos[0] == '/')
		pos = &pos[1];
	if (pos[0] != '\0')
		*attr = pos;
	else
		*attr = NULL;

	pos = strchr(*subsys, '/');
	if (pos == NULL)
		return -1;
	pos[0] = '\0';
	*sysname = &pos[1];
	return 0;
}

static int attr_subst_subdir(char *attr, size_t len)
{
	char *pos;
	int found = 0;

	pos = strstr(attr, "/*/");
	if (pos != NULL) {
		char str[UTIL_PATH_SIZE];
		DIR *dir;

		pos[1] = '\0';
		util_strlcpy(str, &pos[2], sizeof(str));
		dir = opendir(attr);
		if (dir != NULL) {
			struct dirent *dent;

			for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
				struct stat stats;

				if (dent->d_name[0] == '.')
					continue;
				util_strlcat(attr, dent->d_name, len);
				util_strlcat(attr, str, len);
				if (stat(attr, &stats) == 0) {
					found = 1;
					break;
				}
				pos[1] = '\0';
			}
			closedir(dir);
		}
		if (!found)
			util_strlcat(attr, str, len);
	}

	return found;
}

void udev_rules_apply_format(struct udev_event *event, char *string, size_t maxsize)
{
	struct udev_device *dev = event->dev;
	char temp[UTIL_PATH_SIZE];
	char temp2[UTIL_PATH_SIZE];
	char *head, *tail, *cpos, *attr, *rest;
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
					util_strlcpy(temp, head+2, sizeof(temp));
					util_strlcpy(head+1, temp, maxsize);
					head++;
					continue;
				}
				head[0] = '\0';
				for (subst = map; subst->name; subst++) {
					if (strncasecmp(&head[1], subst->name, strlen(subst->name)) == 0) {
						type = subst->type;
						tail = head + strlen(subst->name)+1;
						dbg(event->udev, "will substitute format name '%s'\n", subst->name);
						goto found;
					}
				}
				head[0] = '$';
				err(event->udev, "unknown format variable '%s'\n", head);
			} else if (head[0] == '%') {
				/* substitute format char */
				if (head[1] == '\0')
					break;
				if (head[1] == '%') {
					util_strlcpy(temp, head+2, sizeof(temp));
					util_strlcpy(head+1, temp, maxsize);
					head++;
					continue;
				}
				head[0] = '\0';
				tail = head+1;
				len = get_format_len(event->udev, &tail);
				for (subst = map; subst->name; subst++) {
					if (tail[0] == subst->fmt) {
						type = subst->type;
						tail++;
						dbg(event->udev, "will substitute format char '%c'\n", subst->fmt);
						goto found;
					}
				}
				head[0] = '%';
				err(event->udev, "unknown format char '%c'\n", tail[0]);
			}
			head++;
		}
		break;
found:
		attr = get_format_attribute(event->udev, &tail);
		util_strlcpy(temp, tail, sizeof(temp));
		dbg(event->udev, "format=%i, string='%s', tail='%s'\n", type ,string, tail);

		switch (type) {
		case SUBST_DEVPATH:
			util_strlcat(string, udev_device_get_devpath(dev), maxsize);
			dbg(event->udev, "substitute devpath '%s'\n", udev_device_get_devpath(dev));
			break;
		case SUBST_KERNEL:
			util_strlcat(string, udev_device_get_sysname(dev), maxsize);
			dbg(event->udev, "substitute kernel name '%s'\n", udev_device_get_sysname(dev));
			break;
		case SUBST_KERNEL_NUMBER:
			if (udev_device_get_sysnum(dev) == NULL)
				break;
			util_strlcat(string, udev_device_get_sysnum(dev), maxsize);
			dbg(event->udev, "substitute kernel number '%s'\n", udev_device_get_sysnum(dev));
			break;
		case SUBST_ID:
			if (event->dev_parent != NULL) {
				util_strlcat(string, udev_device_get_sysname(event->dev_parent), maxsize);
				dbg(event->udev, "substitute id '%s'\n", udev_device_get_sysname(event->dev_parent));
			}
			break;
		case SUBST_DRIVER:
			if (event->dev_parent != NULL) {
				const char *driver = udev_device_get_driver(event->dev_parent);

				if (driver == NULL)
					break;
				util_strlcat(string, driver, maxsize);
				dbg(event->udev, "substitute driver '%s'\n", driver);
			}
			break;
		case SUBST_MAJOR:
			sprintf(temp2, "%d", major(udev_device_get_devnum(dev)));
			util_strlcat(string, temp2, maxsize);
			dbg(event->udev, "substitute major number '%s'\n", temp2);
			break;
		case SUBST_MINOR:
			sprintf(temp2, "%d", minor(udev_device_get_devnum(dev)));
			util_strlcat(string, temp2, maxsize);
			dbg(event->udev, "substitute minor number '%s'\n", temp2);
			break;
		case SUBST_RESULT:
			if (event->program_result[0] == '\0')
				break;
			/* get part part of the result string */
			i = 0;
			if (attr != NULL)
				i = strtoul(attr, &rest, 10);
			if (i > 0) {
				dbg(event->udev, "request part #%d of result string\n", i);
				cpos = event->program_result;
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
				util_strlcpy(temp2, cpos, sizeof(temp2));
				/* %{2+}c copies the whole string from the second part on */
				if (rest[0] != '+') {
					cpos = strchr(temp2, ' ');
					if (cpos)
						cpos[0] = '\0';
				}
				util_strlcat(string, temp2, maxsize);
				dbg(event->udev, "substitute part of result string '%s'\n", temp2);
			} else {
				util_strlcat(string, event->program_result, maxsize);
				dbg(event->udev, "substitute result string '%s'\n", event->program_result);
			}
			break;
		case SUBST_ATTR:
			if (attr == NULL)
				err(event->udev, "missing file parameter for attr\n");
			else {
				char *subsys;
				char *sysname;
				char *attrib;
				char value[UTIL_NAME_SIZE] = "";
				size_t size;

				if (split_subsys_sysname(event->udev, attr, &subsys, &sysname, &attrib) == 0) {
					struct udev_device *d;
					const char *val;

					if (attrib == NULL)
						break;
					d = udev_device_new_from_subsystem_sysname(event->udev, subsys, sysname);
					if (d == NULL)
						break;
					val = udev_device_get_attr_value(d, attrib);
					if (val != NULL)
						util_strlcpy(value, val, sizeof(value));
					udev_device_unref(d);
				}

				/* try the current device, other matches may have selected */
				if (value[0]=='\0' && event->dev_parent != NULL && event->dev_parent != event->dev) {
					const char *val;

					val = udev_device_get_attr_value(event->dev_parent, attr);
					if (val != NULL)
						util_strlcpy(value, val, sizeof(value));
				}

				/* look at all devices along the chain of parents */
				if (value[0]=='\0') {
					struct udev_device *dev_parent = dev;
					const char *val;

					do {
						dbg(event->udev, "looking at '%s'\n", udev_device_get_syspath(dev_parent));
						val = udev_device_get_attr_value(dev_parent, attr);
						if (val != NULL) {
							util_strlcpy(value, val, sizeof(value));
							break;
						}
						dev_parent = udev_device_get_parent(dev_parent);
					} while (dev_parent != NULL);
				}

				if (value[0]=='\0')
					break;

				/* strip trailing whitespace, and replace unwanted characters */
				size = strlen(value);
				while (size > 0 && isspace(value[--size]))
					value[size] = '\0';
				count = util_replace_chars(value, ALLOWED_CHARS_INPUT);
				if (count > 0)
					info(event->udev, "%i character(s) replaced\n" , count);
				util_strlcat(string, value, maxsize);
				dbg(event->udev, "substitute sysfs value '%s'\n", value);
			}
			break;
		case SUBST_PARENT:
			{
				struct udev_device *dev_parent;
				const char *devnode;

				dev_parent = udev_device_get_parent(event->dev);
				if (dev_parent == NULL)
					break;
				devnode = udev_device_get_devnode(dev_parent);
				if (devnode != NULL) {
					size_t devlen = strlen(udev_get_dev_path(event->udev))+1;

					util_strlcat(string, &devnode[devlen], maxsize);
					dbg(event->udev, "found parent '%s', got node name '%s'\n",
					    udev_device_get_syspath(dev_parent), &devnode[devlen]);
				}
			}
			break;
		case SUBST_TEMP_NODE:
			if (event->tmp_node[0] == '\0' && major(udev_device_get_devnum(dev)) > 0) {
				dbg(event->udev, "create temporary device node for callout\n");
				snprintf(event->tmp_node, sizeof(event->tmp_node), "%s/.tmp-%u-%u",
					 udev_get_dev_path(event->udev),
					 major(udev_device_get_devnum(dev)), minor(udev_device_get_devnum(dev)));
				udev_node_mknod(dev, event->tmp_node, makedev(0,0), 0600, 0, 0);
			}
			util_strlcat(string, event->tmp_node, maxsize);
			dbg(event->udev, "substitute temporary device node name '%s'\n", event->tmp_node);
			break;
		case SUBST_NAME:
			if (event->name != NULL) {
				util_strlcat(string, event->name, maxsize);
				dbg(event->udev, "substitute name '%s'\n", event->name);
			} else {
				util_strlcat(string, udev_device_get_sysname(dev), maxsize);
				dbg(event->udev, "substitute sysname '%s'\n", udev_device_get_sysname(dev));
			}
			break;
		case SUBST_LINKS:
			{
				struct udev_list_entry *list_entry;

				list_entry = udev_device_get_properties_list_entry(dev);
				util_strlcpy(string, udev_list_entry_get_name(list_entry), maxsize);
				udev_list_entry_foreach(list_entry, udev_list_entry_get_next(list_entry)) {
					util_strlcat(string, " ", maxsize);
					util_strlcat(string, udev_list_entry_get_name(list_entry), maxsize);
				}
			}
			break;
		case SUBST_ROOT:
			util_strlcat(string, udev_get_dev_path(event->udev), maxsize);
			dbg(event->udev, "substitute udev_root '%s'\n", udev_get_dev_path(event->udev));
			break;
		case SUBST_SYS:
			util_strlcat(string, udev_get_sys_path(event->udev), maxsize);
			dbg(event->udev, "substitute sys_path '%s'\n", udev_get_sys_path(event->udev));
			break;
		case SUBST_ENV:
			if (attr == NULL) {
				dbg(event->udev, "missing attribute\n");
				break;
			} else {
				struct udev_list_entry *list_entry;
				const char *value;

				list_entry = udev_device_get_properties_list_entry(event->dev);
				list_entry = udev_list_entry_get_by_name(list_entry, attr);
				if (list_entry == NULL)
					break;
				value = udev_list_entry_get_value(list_entry);
				dbg(event->udev, "substitute env '%s=%s'\n", attr, value);
				util_strlcat(string, value, maxsize);
				break;
			}
		default:
			err(event->udev, "unknown substitution type=%i\n", type);
			break;
		}
		/* possibly truncate to format-char specified length */
		if (len >= 0 && len < (int)strlen(head)) {
			head[len] = '\0';
			dbg(event->udev, "truncate to %i chars, subtitution string becomes '%s'\n", len, head);
		}
		util_strlcat(string, temp, maxsize);
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
	char value[UTIL_PATH_SIZE];
	char *key_value;
	char *pos;
	int match = 0;

	if (key->operation != KEY_OP_MATCH &&
	    key->operation != KEY_OP_NOMATCH)
		return 0;

	if (val == NULL)
		val = "";

	/* look for a matching string, parts are separated by '|' */
	util_strlcpy(value, rule->buf + key->val_off, sizeof(value));
	key_value = value;
	dbg(udev, "key %s value='%s'\n", key_name, key_value);
	while (key_value != NULL) {
		pos = strchr(key_value, '|');
		if (pos != NULL) {
			pos[0] = '\0';
			pos = &pos[1];
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
static int match_rule(struct udev_event *event, struct udev_rule *rule)
{
	struct udev_device *dev = event->dev;
	int i;

	if (match_key(event->udev, "ACTION", rule, &rule->action, udev_device_get_action(dev)))
		goto nomatch;

	if (match_key(event->udev, "KERNEL", rule, &rule->kernel, udev_device_get_sysname(dev)))
		goto nomatch;

	if (match_key(event->udev, "SUBSYSTEM", rule, &rule->subsystem, udev_device_get_subsystem(dev)))
		goto nomatch;

	if (match_key(event->udev, "DEVPATH", rule, &rule->devpath, udev_device_get_devpath(dev)))
		goto nomatch;

	if (match_key(event->udev, "DRIVER", rule, &rule->driver, udev_device_get_driver(dev)))
		goto nomatch;

	/* match NAME against a value assigned by an earlier rule */
	if (match_key(event->udev, "NAME", rule, &rule->name, event->name))
		goto nomatch;

	/* match against current list of symlinks */
	if (rule->symlink_match.operation == KEY_OP_MATCH ||
	    rule->symlink_match.operation == KEY_OP_NOMATCH) {
		size_t devlen = strlen(udev_get_dev_path(event->udev))+1;
		struct udev_list_entry *list_entry;
		int match = 0;

		udev_list_entry_foreach(list_entry, udev_device_get_devlinks_list_entry(dev)) {
			const char *devlink;

			devlink =  &udev_list_entry_get_name(list_entry)[devlen];
			if (match_key(event->udev, "SYMLINK", rule, &rule->symlink_match, devlink) == 0) {
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
			struct udev_list_entry *list_entry;
			const char *key_name = key_pair_name(rule, pair);
			const char *value;

			list_entry = udev_device_get_properties_list_entry(event->dev);
			list_entry = udev_list_entry_get_by_name(list_entry, key_name);
			value = udev_list_entry_get_value(list_entry);
			if (value == NULL) {
				dbg(event->udev, "ENV{%s} is not set, treat as empty\n", key_name);
				value = "";
			}
			if (match_key(event->udev, "ENV", rule, &pair->key, value))
				goto nomatch;
		}
	}

	if (rule->test.operation == KEY_OP_MATCH ||
	    rule->test.operation == KEY_OP_NOMATCH) {
		char filename[UTIL_PATH_SIZE];
		char *subsys;
		char *sysname;
		char *attrib;
		struct stat statbuf;
		int match;

		util_strlcpy(filename, key_val(rule, &rule->test), sizeof(filename));
		udev_rules_apply_format(event, filename, sizeof(filename));

		if (split_subsys_sysname(event->udev, filename, &subsys, &sysname, &attrib) == 0) {
			struct udev_device *d;
			d = udev_device_new_from_subsystem_sysname(event->udev, subsys, sysname);
			if (d != NULL) {
				util_strlcpy(filename, udev_device_get_syspath(d), sizeof(filename));
				if (attrib != NULL) {
					util_strlcat(filename, "/", sizeof(filename));
					util_strlcat(filename, attrib, sizeof(filename));
				}
				udev_device_unref(d);
			}
		} else if (filename[0] != '/') {
			char tmp[UTIL_PATH_SIZE];

			util_strlcpy(tmp, udev_device_get_syspath(dev), sizeof(tmp));
			util_strlcat(tmp, "/", sizeof(tmp));
			util_strlcat(tmp, filename, sizeof(tmp));
			util_strlcpy(filename, tmp, sizeof(filename));
		}

		attr_subst_subdir(filename, sizeof(filename));

		match = (stat(filename, &statbuf) == 0);
		info(event->udev, "'%s' %s", filename, match ? "exists\n" : "does not exist\n");
		if (match && rule->test_mode_mask > 0) {
			match = ((statbuf.st_mode & rule->test_mode_mask) > 0);
			info(event->udev, "'%s' has mode=%#o and %s %#o\n", filename, statbuf.st_mode,
			     match ? "matches" : "does not match",
			     rule->test_mode_mask);
		}
		if (match && rule->test.operation == KEY_OP_NOMATCH)
			goto nomatch;
		if (!match && rule->test.operation == KEY_OP_MATCH)
			goto nomatch;
		dbg(event->udev, "TEST key is true\n");
	}

	if (rule->wait_for.operation != KEY_OP_UNSET) {
		char filename[UTIL_PATH_SIZE];
		int found;

		util_strlcpy(filename, key_val(rule, &rule->wait_for), sizeof(filename));
		udev_rules_apply_format(event, filename, sizeof(filename));
		found = (wait_for_file(event, filename, 10) == 0);
		if (!found && (rule->wait_for.operation != KEY_OP_NOMATCH))
			goto nomatch;
	}

	/* check for matching sysfs attribute pairs */
	for (i = 0; i < rule->attr.count; i++) {
		struct key_pair *pair = &rule->attr.keys[i];

		if (pair->key.operation == KEY_OP_MATCH ||
		    pair->key.operation == KEY_OP_NOMATCH) {
			char attr[UTIL_PATH_SIZE];
			const char *key_name = key_pair_name(rule, pair);
			const char *key_value = key_val(rule, &pair->key);
			char *subsys;
			char *sysname;
			char *attrib;
			char value[UTIL_NAME_SIZE] = "";
			size_t len;

			util_strlcpy(attr, key_name, sizeof(attr));
			if (split_subsys_sysname(event->udev, attr, &subsys, &sysname, &attrib) == 0) {
				struct udev_device *d;
				const char *val;

				if (attrib == NULL)
					goto nomatch;
				d = udev_device_new_from_subsystem_sysname(event->udev, subsys, sysname);
				if (d == NULL)
					goto nomatch;
				val = udev_device_get_attr_value(d, attrib);
				if (val != NULL)
					util_strlcpy(value, val, sizeof(value));
				udev_device_unref(d);
			}

			if (value[0]=='\0') {
				const char *val;

				val = udev_device_get_attr_value(dev, key_name);
				if (val != NULL)
					util_strlcpy(value, val, sizeof(value));
			}

			if (value[0]=='\0')
				goto nomatch;

			/* strip trailing whitespace of value, if not asked to match for it */
			len = strlen(key_value);
			if (len > 0 && !isspace(key_value[len-1])) {
				len = strlen(value);
				while (len > 0 && isspace(value[--len]))
					value[len] = '\0';
				dbg(event->udev, "removed trailing whitespace from '%s'\n", value);
			}

			if (match_key(event->udev, "ATTR", rule, &pair->key, value))
				goto nomatch;
		}
	}

	/* walk up the chain of parent devices and find a match */
	event->dev_parent = dev;
	while (1) {
		/* check for matching kernel device name */
		if (match_key(event->udev, "KERNELS", rule,
			      &rule->kernels, udev_device_get_sysname(event->dev_parent)))
			goto try_parent;

		/* check for matching subsystem value */
		if (match_key(event->udev, "SUBSYSTEMS", rule,
			      &rule->subsystems, udev_device_get_subsystem(event->dev_parent)))
			goto try_parent;

		/* check for matching driver */
		if (match_key(event->udev, "DRIVERS", rule,
			      &rule->drivers, udev_device_get_driver(event->dev_parent)))
			goto try_parent;

		/* check for matching sysfs attribute pairs */
		for (i = 0; i < rule->attrs.count; i++) {
			struct key_pair *pair = &rule->attrs.keys[i];

			if (pair->key.operation == KEY_OP_MATCH ||
			    pair->key.operation == KEY_OP_NOMATCH) {
				const char *key_name = key_pair_name(rule, pair);
				const char *key_value = key_val(rule, &pair->key);
				const char *val;
				char value[UTIL_NAME_SIZE];
				size_t len;

				val = udev_device_get_attr_value(event->dev_parent, key_name);
				if (val == NULL)
					val = udev_device_get_attr_value(dev, key_name);
				if (val == NULL)
					goto try_parent;
				util_strlcpy(value, val, sizeof(value));

				/* strip trailing whitespace of value, if not asked to match for it */
				len = strlen(key_value);
				if (len > 0 && !isspace(key_value[len-1])) {
					len = strlen(value);
					while (len > 0 && isspace(value[--len]))
						value[len] = '\0';
					dbg(event->udev, "removed trailing whitespace from '%s'\n", value);
				}

				if (match_key(event->udev, "ATTRS", rule, &pair->key, value))
					goto try_parent;
			}
		}

		/* found matching device  */
		break;
try_parent:
		/* move to parent device */
		dbg(event->udev, "try parent sysfs device\n");
		event->dev_parent = udev_device_get_parent(event->dev_parent);
		if (event->dev_parent == NULL)
			goto nomatch;
		dbg(event->udev, "looking at dev_parent->devpath='%s'\n",
		    udev_device_get_syspath(event->dev_parent));
	}

	/* execute external program */
	if (rule->program.operation != KEY_OP_UNSET) {
		char program[UTIL_PATH_SIZE];
		char result[UTIL_PATH_SIZE];

		util_strlcpy(program, key_val(rule, &rule->program), sizeof(program));
		udev_rules_apply_format(event, program, sizeof(program));
		if (run_program(event->dev, program, result, sizeof(result), NULL) != 0) {
			dbg(event->udev, "PROGRAM is false\n");
			event->program_result[0] = '\0';
			if (rule->program.operation != KEY_OP_NOMATCH)
				goto nomatch;
		} else {
			int count;

			dbg(event->udev, "PROGRAM matches\n");
			util_remove_trailing_chars(result, '\n');
			if (rule->string_escape == ESCAPE_UNSET ||
			    rule->string_escape == ESCAPE_REPLACE) {
				count = util_replace_chars(result, ALLOWED_CHARS_INPUT);
				if (count > 0)
					info(event->udev, "%i character(s) replaced\n" , count);
			}
			dbg(event->udev, "result is '%s'\n", result);
			util_strlcpy(event->program_result, result, sizeof(event->program_result));
			dbg(event->udev, "PROGRAM returned successful\n");
			if (rule->program.operation == KEY_OP_NOMATCH)
				goto nomatch;
		}
		dbg(event->udev, "PROGRAM key is true\n");
	}

	/* check for matching result of external program */
	if (match_key(event->udev, "RESULT", rule, &rule->result, event->program_result))
		goto nomatch;

	/* import variables returned from program or or file into environment */
	if (rule->import.operation != KEY_OP_UNSET) {
		char import[UTIL_PATH_SIZE];
		int rc = -1;

		util_strlcpy(import, key_val(rule, &rule->import), sizeof(import));
		udev_rules_apply_format(event, import, sizeof(import));
		dbg(event->udev, "check for IMPORT import='%s'\n", import);
		if (rule->import_type == IMPORT_PROGRAM) {
			rc = import_program_into_env(event->dev, import);
		} else if (rule->import_type == IMPORT_FILE) {
			dbg(event->udev, "import file import='%s'\n", import);
			rc = import_file_into_env(event->dev, import);
		} else if (rule->import_type == IMPORT_PARENT) {
			dbg(event->udev, "import parent import='%s'\n", import);
			rc = import_parent_into_env(event->dev, import);
		}
		if (rc != 0) {
			dbg(event->udev, "IMPORT failed\n");
			if (rule->import.operation != KEY_OP_NOMATCH)
				goto nomatch;
		} else
			dbg(event->udev, "IMPORT '%s' imported\n", key_val(rule, &rule->import));
		dbg(event->udev, "IMPORT key is true\n");
	}

	/* rule matches, if we have ENV assignments export it */
	for (i = 0; i < rule->env.count; i++) {
		struct key_pair *pair = &rule->env.keys[i];

		if (pair->key.operation == KEY_OP_ASSIGN) {
			char temp_value[UTIL_NAME_SIZE];
			const char *key_name = key_pair_name(rule, pair);
			const char *value = key_val(rule, &pair->key);

			/* make sure we don't write to the same string we possibly read from */
			util_strlcpy(temp_value, value, sizeof(temp_value));
			udev_rules_apply_format(event, temp_value, sizeof(temp_value));

			if (temp_value[0] != '\0') {
				struct udev_list_entry *entry;

				info(event->udev, "set ENV '%s=%s'\n", key_name, temp_value);
				entry = udev_device_add_property(dev, key_name, temp_value);
				/* store in db */
				udev_list_entry_set_flag(entry, 1);
			}
		}
	}

	/* if we have ATTR assignments, write value to sysfs file */
	for (i = 0; i < rule->attr.count; i++) {
		struct key_pair *pair = &rule->attr.keys[i];

		if (pair->key.operation == KEY_OP_ASSIGN) {
			const char *key_name = key_pair_name(rule, pair);
			char *subsys;
			char *sysname;
			char *attrib;
			char attr[UTIL_PATH_SIZE];
			char value[UTIL_NAME_SIZE];
			FILE *f;

			util_strlcpy(attr, key_name, sizeof(attr));
			if (split_subsys_sysname(event->udev, attr, &subsys, &sysname, &attrib) == 0) {
				struct udev_device *d;

				d = udev_device_new_from_subsystem_sysname(event->udev, subsys, sysname);
				if (d != NULL) {
					util_strlcpy(attr, udev_device_get_syspath(d), sizeof(attr));
					if (attrib != NULL) {
						util_strlcat(attr, "/", sizeof(attr));
						util_strlcat(attr, attrib, sizeof(attr));
					}
					udev_device_unref(d);
				}
			} else {
				util_strlcpy(attr, udev_device_get_syspath(dev), sizeof(attr));
				util_strlcat(attr, "/", sizeof(attr));
				util_strlcat(attr, key_name, sizeof(attr));
			}

			attr_subst_subdir(attr, sizeof(attr));

			util_strlcpy(value, key_val(rule, &pair->key), sizeof(value));
			udev_rules_apply_format(event, value, sizeof(value));
			info(event->udev, "writing '%s' to sysfs file '%s'\n", value, attr);
			f = fopen(attr, "w");
			if (f != NULL) {
				if (!event->test)
					if (fprintf(f, "%s", value) <= 0)
						err(event->udev, "error writing ATTR{%s}: %m\n", attr);
				fclose(f);
			} else
				err(event->udev, "error opening ATTR{%s} for writing: %m\n", attr);
		}
	}
	return 0;

nomatch:
	return -1;
}

int udev_rules_get_name(struct udev_rules *rules, struct udev_event *event)
{
	struct udev_device *dev = event->dev;
	struct udev_rules_iter iter;
	struct udev_rule *rule;
	int name_set = 0;

	dbg(event->udev, "device: '%s'\n", udev_device_get_syspath(dev));

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
			dbg(event->udev, "node name already set, rule ignored\n");
			continue;
		}

		dbg(event->udev, "process rule\n");
		if (match_rule(event, rule) == 0) {
			/* apply options */
			if (rule->ignore_device) {
				info(event->udev, "rule applied, '%s' is ignored\n", udev_device_get_sysname(dev));
				event->ignore_device = 1;
				return 0;
			}
			if (rule->ignore_remove) {
				udev_device_set_ignore_remove(dev, 1);
				dbg(event->udev, "remove event should be ignored\n");
			}
			if (rule->link_priority != 0) {
				udev_device_set_devlink_priority(dev, rule->link_priority);
				info(event->udev, "devlink_priority=%i\n", rule->link_priority);
			}
			if (rule->event_timeout >= 0) {
				udev_device_set_event_timeout(dev, rule->event_timeout);
				info(event->udev, "event_timeout=%i\n", rule->event_timeout);
			}
			/* apply all_partitions option only at a disk device */
			if (rule->partitions > 0 &&
			    strcmp(udev_device_get_subsystem(dev), "block") == 0 &&
			    udev_device_get_sysnum(dev) == NULL) {
				udev_device_set_num_fake_partitions(dev, rule->partitions);
				dbg(event->udev, "creation of partition nodes requested\n");
			}

			/* apply permissions */
			if (!event->mode_final && rule->mode.operation != KEY_OP_UNSET) {
				if (rule->mode.operation == KEY_OP_ASSIGN_FINAL)
					event->mode_final = 1;
				char buf[20];
				util_strlcpy(buf, key_val(rule, &rule->mode), sizeof(buf));
				udev_rules_apply_format(event, buf, sizeof(buf));
				event->mode = strtol(buf, NULL, 8);
				dbg(event->udev, "applied mode=%#o to '%s'\n",
				    event->mode, udev_device_get_sysname(dev));
			}
			if (!event->owner_final && rule->owner.operation != KEY_OP_UNSET) {
				if (rule->owner.operation == KEY_OP_ASSIGN_FINAL)
					event->owner_final = 1;
				util_strlcpy(event->owner, key_val(rule, &rule->owner), sizeof(event->owner));
				udev_rules_apply_format(event, event->owner, sizeof(event->owner));
				dbg(event->udev, "applied owner='%s' to '%s'\n",
				    event->owner, udev_device_get_sysname(dev));
			}
			if (!event->group_final && rule->group.operation != KEY_OP_UNSET) {
				if (rule->group.operation == KEY_OP_ASSIGN_FINAL)
					event->group_final = 1;
				util_strlcpy(event->group, key_val(rule, &rule->group), sizeof(event->group));
				udev_rules_apply_format(event, event->group, sizeof(event->group));
				dbg(event->udev, "applied group='%s' to '%s'\n",
				    event->group, udev_device_get_sysname(dev));
			}

			/* collect symlinks */
			if (!event->devlink_final &&
			    (rule->symlink.operation == KEY_OP_ASSIGN ||
			     rule->symlink.operation == KEY_OP_ASSIGN_FINAL ||
			     rule->symlink.operation == KEY_OP_ADD)) {
				char temp[UTIL_PATH_SIZE];
				char filename[UTIL_PATH_SIZE];
				char *pos, *next;
				int count = 0;

				if (rule->symlink.operation == KEY_OP_ASSIGN_FINAL)
					event->devlink_final = 1;
				if (rule->symlink.operation == KEY_OP_ASSIGN ||
				    rule->symlink.operation == KEY_OP_ASSIGN_FINAL) {
					info(event->udev, "reset symlink list\n");
					udev_device_cleanup_devlinks_list(dev);
				}
				/* allow  multiple symlinks separated by spaces */
				util_strlcpy(temp, key_val(rule, &rule->symlink), sizeof(temp));
				udev_rules_apply_format(event, temp, sizeof(temp));
				if (rule->string_escape == ESCAPE_UNSET)
					count = util_replace_chars(temp, ALLOWED_CHARS_FILE " ");
				else if (rule->string_escape == ESCAPE_REPLACE)
					count = util_replace_chars(temp, ALLOWED_CHARS_FILE);
				if (count > 0)
					info(event->udev, "%i character(s) replaced\n" , count);
				dbg(event->udev, "rule applied, added symlink(s) '%s'\n", temp);
				pos = temp;
				while (isspace(pos[0]))
					pos++;
				next = strchr(pos, ' ');
				while (next) {
					next[0] = '\0';
					info(event->udev, "add symlink '%s'\n", pos);
					util_strlcpy(filename, udev_get_dev_path(event->udev), sizeof(filename));
					util_strlcat(filename, "/", sizeof(filename));
					util_strlcat(filename, pos, sizeof(filename));
					udev_device_add_devlink(dev, filename);
					while (isspace(next[1]))
						next++;
					pos = &next[1];
					next = strchr(pos, ' ');
				}
				if (pos[0] != '\0') {
					info(event->udev, "add symlink '%s'\n", pos);
					util_strlcpy(filename, udev_get_dev_path(event->udev), sizeof(filename));
					util_strlcat(filename, "/", sizeof(filename));
					util_strlcat(filename, pos, sizeof(filename));
					udev_device_add_devlink(dev, filename);
				}
			}

			/* set name, later rules with name set will be ignored */
			if (rule->name.operation == KEY_OP_ASSIGN ||
			    rule->name.operation == KEY_OP_ASSIGN_FINAL ||
			    rule->name.operation == KEY_OP_ADD) {
				int count;

				name_set = 1;
				util_strlcpy(event->name, key_val(rule, &rule->name), sizeof(event->name));
				udev_rules_apply_format(event, event->name, sizeof(event->name));
				if (rule->string_escape == ESCAPE_UNSET ||
				    rule->string_escape == ESCAPE_REPLACE) {
					count = util_replace_chars(event->name, ALLOWED_CHARS_FILE);
					if (count > 0)
						info(event->udev, "%i character(s) replaced\n", count);
				}

				info(event->udev, "rule applied, '%s' becomes '%s'\n",
				     udev_device_get_sysname(dev), event->name);
				if (strcmp(udev_device_get_subsystem(dev), "net") != 0)
					dbg(event->udev, "'%s' owner='%s', group='%s', mode=%#o partitions=%i\n",
					    event->name, event->owner, event->group, event->mode,
					    udev_device_get_num_fake_partitions(dev));
			}

			if (!event->run_final && rule->run.operation != KEY_OP_UNSET) {
				struct udev_list_entry *list_entry;

				if (rule->run.operation == KEY_OP_ASSIGN_FINAL)
					event->run_final = 1;
				if (rule->run.operation == KEY_OP_ASSIGN || rule->run.operation == KEY_OP_ASSIGN_FINAL) {
					info(event->udev, "reset run list\n");
					udev_list_cleanup(event->udev, &event->run_list);
				}
				dbg(event->udev, "add run '%s'\n", key_val(rule, &rule->run));
				list_entry = udev_list_entry_add(event->udev, &event->run_list,
								 key_val(rule, &rule->run), NULL, 1, 0);
				if (rule->run_ignore_error && list_entry != NULL)
					udev_list_entry_set_flag(list_entry, 1);
			}

			if (rule->last_rule) {
				dbg(event->udev, "last rule to be applied\n");
				break;
			}

			if (rule->goto_label.operation != KEY_OP_UNSET) {
				dbg(event->udev, "moving forward to label '%s'\n", key_val(rule, &rule->goto_label));
				udev_rules_iter_goto(&iter, rule->goto_rule_off);
			}
		}
	}

	if (!name_set) {
		info(event->udev, "no node name set, will use kernel name '%s'\n",
		     udev_device_get_sysname(dev));
		util_strlcpy(event->name, udev_device_get_sysname(dev), sizeof(event->name));
	}

	if (event->tmp_node[0] != '\0') {
		dbg(event->udev, "removing temporary device node\n");
		unlink_secure(event->udev, event->tmp_node);
		event->tmp_node[0] = '\0';
	}
	return 0;
}

int udev_rules_get_run(struct udev_rules *rules, struct udev_event *event)
{
	struct udev_device *dev = event->dev;
	struct udev_rules_iter iter;
	struct udev_rule *rule;

	dbg(event->udev, "sysname: '%s'\n", udev_device_get_sysname(dev));

	/* look for a matching rule to apply */
	udev_rules_iter_init(&iter, rules);
	while (1) {
		rule = udev_rules_iter_next(&iter);
		if (rule == NULL)
			break;

		dbg(event->udev, "process rule\n");
		if (rule->name.operation == KEY_OP_ASSIGN ||
		    rule->name.operation == KEY_OP_ASSIGN_FINAL ||
		    rule->name.operation == KEY_OP_ADD ||
		    rule->symlink.operation == KEY_OP_ASSIGN ||
		    rule->symlink.operation == KEY_OP_ASSIGN_FINAL ||
		    rule->symlink.operation == KEY_OP_ADD ||
		    rule->mode.operation != KEY_OP_UNSET ||
		    rule->owner.operation != KEY_OP_UNSET || rule->group.operation != KEY_OP_UNSET) {
			dbg(event->udev, "skip rule that names a device\n");
			continue;
		}

		if (match_rule(event, rule) == 0) {
			if (rule->ignore_device) {
				info(event->udev, "rule applied, '%s' is ignored\n", udev_device_get_sysname(dev));
				event->ignore_device = 1;
				return 0;
			}
			if (rule->ignore_remove) {
				udev_device_set_ignore_remove(dev, 1);
				dbg(event->udev, "remove event should be ignored\n");
			}

			if (!event->run_final && rule->run.operation != KEY_OP_UNSET) {
				struct udev_list_entry *list_entry;

				if (rule->run.operation == KEY_OP_ASSIGN ||
				    rule->run.operation == KEY_OP_ASSIGN_FINAL) {
					info(event->udev, "reset run list\n");
					udev_list_cleanup(event->udev, &event->run_list);
				}
				dbg(event->udev, "add run '%s'\n", key_val(rule, &rule->run));
				list_entry = udev_list_entry_add(event->udev, &event->run_list,
								 key_val(rule, &rule->run), NULL, 1, 0);
				if (rule->run_ignore_error && list_entry != NULL)
					udev_list_entry_set_flag(list_entry, 1);
				if (rule->run.operation == KEY_OP_ASSIGN_FINAL)
					break;
			}

			if (rule->last_rule) {
				dbg(event->udev, "last rule to be applied\n");
				break;
			}

			if (rule->goto_label.operation != KEY_OP_UNSET) {
				dbg(event->udev, "moving forward to label '%s'\n", key_val(rule, &rule->goto_label));
				udev_rules_iter_goto(&iter, rule->goto_rule_off);
			}
		}
	}

	return 0;
}
