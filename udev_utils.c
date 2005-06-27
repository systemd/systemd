/*
 * udev_lib - generic stuff used by udev
 *
 * Copyright (C) 2004 Kay Sievers <kay@vrfy.org>
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
#include <dirent.h>
#include <syslog.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/utsname.h>

#include "udev_libc_wrapper.h"
#include "udev.h"
#include "logging.h"
#include "udev_utils.h"
#include "list.h"


int udev_init_device(struct udevice *udev, const char* devpath, const char *subsystem, const char *action)
{
	char *pos;

	memset(udev, 0x00, sizeof(struct udevice));
	INIT_LIST_HEAD(&udev->symlink_list);
	INIT_LIST_HEAD(&udev->run_list);
	INIT_LIST_HEAD(&udev->env_list);

	if (subsystem)
		strlcpy(udev->subsystem, subsystem, sizeof(udev->subsystem));

	if (action)
		strlcpy(udev->action, action, sizeof(udev->action));

	if (devpath) {
		strlcpy(udev->devpath, devpath, sizeof(udev->devpath));
		remove_trailing_char(udev->devpath, '/');

		if (strncmp(udev->devpath, "/block/", 7) == 0)
			udev->type = DEV_BLOCK;
		else if (strncmp(udev->devpath, "/class/net/", 11) == 0)
			udev->type = DEV_NET;
		else if (strncmp(udev->devpath, "/class/", 7) == 0)
			udev->type = DEV_CLASS;
		else if (strncmp(udev->devpath, "/devices/", 9) == 0)
			udev->type = DEV_DEVICE;

		/* get kernel name */
		pos = strrchr(udev->devpath, '/');
		if (pos) {
			strlcpy(udev->kernel_name, &pos[1], sizeof(udev->kernel_name));
			dbg("kernel_name='%s'", udev->kernel_name);

			/* Some block devices have '!' in their name, change that to '/' */
			pos = udev->kernel_name;
			while (pos[0] != '\0') {
				if (pos[0] == '!')
					pos[0] = '/';
				pos++;
			}

			/* get kernel number */
			pos = &udev->kernel_name[strlen(udev->kernel_name)];
			while (isdigit(pos[-1]))
				pos--;
			strlcpy(udev->kernel_number, pos, sizeof(udev->kernel_number));
			dbg("kernel_number='%s'", udev->kernel_number);
		}
	}

	if (udev->type == DEV_BLOCK || udev->type == DEV_CLASS) {
		udev->mode = 0660;
		strcpy(udev->owner, "root");
		strcpy(udev->group, "root");
	}

	return 0;
}

void udev_cleanup_device(struct udevice *udev)
{
	struct name_entry *name_loop;
	struct name_entry *temp_loop;

	list_for_each_entry_safe(name_loop, temp_loop, &udev->symlink_list, node) {
		list_del(&name_loop->node);
		free(name_loop);
	}
	list_for_each_entry_safe(name_loop, temp_loop, &udev->run_list, node) {
		list_del(&name_loop->node);
		free(name_loop);
	}
	list_for_each_entry_safe(name_loop, temp_loop, &udev->env_list, node) {
		list_del(&name_loop->node);
		free(name_loop);
	}
}

int string_is_true(const char *str)
{
	if (strcasecmp(str, "true") == 0)
		return 1;
	if (strcasecmp(str, "yes") == 0)
		return 1;
	if (strcasecmp(str, "1") == 0)
		return 1;
	return 0;
}

int log_priority(const char *priority)
{
	char *endptr;
	int prio;

	prio = strtol(priority, &endptr, 10);
	if (endptr[0] == '\0')
		return prio;
	if (strncasecmp(priority, "err", 3) == 0)
		return LOG_ERR;
	if (strcasecmp(priority, "info") == 0)
		return LOG_INFO;
	if (strcasecmp(priority, "debug") == 0)
		return LOG_DEBUG;
	if (string_is_true(priority))
		return LOG_ERR;

	return 0;
}

int kernel_release_satisfactory(unsigned int version, unsigned int patchlevel, unsigned int sublevel)
{
	static unsigned int kversion = 0;
	static unsigned int kpatchlevel;
	static unsigned int ksublevel;

	if (kversion == 0) {
		struct utsname uts;
		if (uname(&uts) != 0)
			return -1;

		if (sscanf (uts.release, "%u.%u.%u", &kversion, &kpatchlevel, &ksublevel) != 3) {
			kversion = 0;
			return -1;
		}
	}

	if (kversion >= version && kpatchlevel >= patchlevel && ksublevel >= sublevel)
		return 1;
	else
		return 0;
}

int create_path(const char *path)
{
	char p[PATH_SIZE];
	char *pos;
	struct stat stats;

	strcpy (p, path);
	pos = strrchr(p, '/');
	if (pos == p || pos == NULL)
		return 0;

	while (pos[-1] == '/')
		pos--;

	pos[0] = '\0';

	dbg("stat '%s'\n", p);
	if (stat (p, &stats) == 0 && (stats.st_mode & S_IFMT) == S_IFDIR)
		return 0;

	if (create_path (p) != 0)
		return -1;

	dbg("mkdir '%s'\n", p);
	return mkdir(p, 0755);
}

/* Reset permissions on the device node, before unlinking it to make sure,
 * that permisions of possible hard links will be removed too.
 */
int unlink_secure(const char *filename)
{
	int retval;

	retval = chown(filename, 0, 0);
	if (retval)
		dbg("chown(%s, 0, 0) failed with error '%s'", filename, strerror(errno));

	retval = chmod(filename, 0000);
	if (retval)
		dbg("chmod(%s, 0000) failed with error '%s'", filename, strerror(errno));

	retval = unlink(filename);
	if (errno == ENOENT)
		retval = 0;

	if (retval)
		dbg("unlink(%s) failed with error '%s'", filename, strerror(errno));

	return retval;
}

int file_map(const char *filename, char **buf, size_t *bufsize)
{
	struct stat stats;
	int fd;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		return -1;
	}

	if (fstat(fd, &stats) < 0) {
		close(fd);
		return -1;
	}

	*buf = mmap(NULL, stats.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (*buf == MAP_FAILED) {
		close(fd);
		return -1;
	}
	*bufsize = stats.st_size;

	close(fd);

	return 0;
}

void file_unmap(void *buf, size_t bufsize)
{
	munmap(buf, bufsize);
}

/* return number of chars until the next newline, skip escaped newline */
size_t buf_get_line(const char *buf, size_t buflen, size_t cur)
{
	int escape = 0;
	size_t count;

	for (count = cur; count < buflen; count++) {
		if (!escape && buf[count] == '\n')
			break;

		if (buf[count] == '\\')
			escape = 1;
		else
			escape = 0;
	}

	return count - cur;
}

void replace_untrusted_chars(char *string)
{
	size_t len;

	for (len = 0; string[len] != '\0'; len++) {
		if (strchr(";,~\\()\'", string[len])) {
			info("replace '%c' in '%s'", string[len], string);
			string[len] = '_';
		}
	}
}

void remove_trailing_char(char *path, char c)
{
	size_t len;

	len = strlen(path);
	while (len > 0 && path[len-1] == c)
		path[--len] = '\0';
}

int name_list_add(struct list_head *name_list, const char *name, int sort)
{
	struct name_entry *loop_name;
	struct name_entry *new_name;

	list_for_each_entry(loop_name, name_list, node) {
		/* avoid doubles */
		if (strcmp(loop_name->name, name) == 0) {
			dbg("'%s' is already in the list", name);
			return 0;
		}
	}

	if (sort)
		list_for_each_entry(loop_name, name_list, node) {
			if (sort && strcmp(loop_name->name, name) > 0)
				break;
		}

	new_name = malloc(sizeof(struct name_entry));
	if (new_name == NULL) {
		dbg("error malloc");
		return -ENOMEM;
	}

	strlcpy(new_name->name, name, sizeof(new_name->name));
	dbg("adding '%s'", new_name->name);
	list_add_tail(&new_name->node, &loop_name->node);

	return 0;
}

int name_list_key_add(struct list_head *name_list, const char *key, const char *value)
{
	struct name_entry *loop_name;
	struct name_entry *new_name;

	list_for_each_entry(loop_name, name_list, node) {
		if (strncmp(loop_name->name, key, strlen(key)) == 0) {
			dbg("key already present '%s', replace it", loop_name->name);
			snprintf(loop_name->name, sizeof(loop_name->name), "%s=%s", key, value);
			loop_name->name[sizeof(loop_name->name)-1] = '\0';
			return 0;
		}
	}

	new_name = malloc(sizeof(struct name_entry));
	if (new_name == NULL) {
		dbg("error malloc");
		return -ENOMEM;
	}

	snprintf(new_name->name, sizeof(new_name->name), "%s=%s", key, value);
	new_name->name[sizeof(new_name->name)-1] = '\0';
	dbg("adding '%s'", new_name->name);
	list_add_tail(&new_name->node, &loop_name->node);

	return 0;
}

/* calls function for every file found in specified directory */
int add_matching_files(struct list_head *name_list, const char *dirname, const char *suffix)
{
	struct dirent *ent;
	DIR *dir;
	char *ext;
	char filename[PATH_SIZE];

	dbg("open directory '%s'", dirname);
	dir = opendir(dirname);
	if (dir == NULL) {
		dbg("unable to open '%s'", dirname);
		return -1;
	}

	while (1) {
		ent = readdir(dir);
		if (ent == NULL || ent->d_name[0] == '\0')
			break;

		if ((ent->d_name[0] == '.') || (ent->d_name[0] == COMMENT_CHARACTER))
			continue;

		/* look for file matching with specified suffix */
		ext = strrchr(ent->d_name, '.');
		if (ext == NULL)
			continue;

		if (strcmp(ext, suffix) != 0)
			continue;

		dbg("put file '%s/%s' in list", dirname, ent->d_name);

		snprintf(filename, sizeof(filename), "%s/%s", dirname, ent->d_name);
		filename[sizeof(filename)-1] = '\0';
		name_list_add(name_list, filename, 1);
	}

	closedir(dir);
	return 0;
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
