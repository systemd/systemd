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
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/utsname.h>

#include "udev_libc_wrapper.h"
#include "udev.h"
#include "logging.h"
#include "udev_utils.h"
#include "list.h"


int udev_init_device(struct udevice *udev, const char* devpath, const char *subsystem)
{
	char *pos;

	memset(udev, 0x00, sizeof(struct udevice));
	INIT_LIST_HEAD(&udev->symlink_list);

	if (subsystem)
		strlcpy(udev->subsystem, subsystem, sizeof(udev->subsystem));

	if (devpath) {
		strlcpy(udev->devpath, devpath, sizeof(udev->devpath));
		no_trailing_slash(udev->devpath);

		if (strncmp(udev->devpath, "/block/", 7) == 0)
			udev->type = BLOCK;
		else if (strncmp(udev->devpath, "/class/net/", 11) == 0)
			udev->type = NET;
		else if (strncmp(udev->devpath, "/class/", 7) == 0)
			udev->type = CLASS;
		else if (strncmp(udev->devpath, "/devices/", 9) == 0)
			udev->type = PHYSDEV;

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

	udev->mode = 0660;
	strcpy(udev->owner, "root");
	strcpy(udev->group, "root");

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

int parse_get_pair(char **orig_string, char **left, char **right)
{
	char *temp;
	char *string = *orig_string;

	if (!string)
		return -ENODEV;

	/* eat any whitespace */
	while (isspace(*string) || *string == ',')
		++string;

	/* split based on '=' */
	temp = strsep(&string, "=");
	*left = temp;
	if (!string)
		return -ENODEV;

	/* take the right side and strip off the '"' */
	while (isspace(string[0]))
		++string;
	if (string[0] == '"')
		++string;
	else
		return -ENODEV;

	temp = strsep(&string, "\"");
	if (!string || temp[0] == '\0')
		return -ENODEV;
	*right = temp;
	*orig_string = string;

	return 0;
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

void file_unmap(char *buf, size_t bufsize)
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

void no_trailing_slash(char *path)
{
	size_t len;

	len = strlen(path);
	while (len > 0 && path[len-1] == '/')
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
		if (sort && strcmp(loop_name->name, name) > 0)
			break;
	}

	new_name = malloc(sizeof(struct name_entry));
	if (new_name == NULL) {
		dbg("error malloc");
		return -ENOMEM;
	}

	strlcpy(new_name->name, name, sizeof(new_name->name));
	list_add_tail(&new_name->node, &loop_name->node);

	return 0;
}

/* calls function for every file found in specified directory */
int call_foreach_file(int (*handler_function)(struct udevice *udev, const char *string),
		      struct udevice *udev, const char *dirname, const char *suffix)
{
	struct dirent *ent;
	DIR *dir;
	char *ext;
	struct name_entry *loop_file;
	struct name_entry *tmp_file;
	LIST_HEAD(file_list);

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

		/* look for file with specified suffix */
		ext = strrchr(ent->d_name, '.');
		if (ext == NULL)
			continue;

		if (strcmp(ext, suffix) != 0)
			continue;

		dbg("put file '%s/%s' in list", dirname, ent->d_name);
		name_list_add(&file_list, ent->d_name, 1);
	}

	/* call function for every file in the list */
	list_for_each_entry_safe(loop_file, tmp_file, &file_list, node) {
		char filename[PATH_SIZE];

		snprintf(filename, sizeof(filename), "%s/%s", dirname, loop_file->name);
		filename[sizeof(filename)-1] = '\0';

		handler_function(udev, filename);

		list_del(&loop_file->node);
		free(loop_file);
	}

	closedir(dir);
	return 0;
}
