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

#include "udev.h"
#include "logging.h"
#include "udev_utils.h"
#include "list.h"


void udev_init_device(struct udevice *udev, const char* devpath, const char *subsystem)
{
	memset(udev, 0x00, sizeof(struct udevice));

	if (devpath)
		strfieldcpy(udev->devpath, devpath);
	if (subsystem)
		strfieldcpy(udev->subsystem, subsystem);

	if (strcmp(udev->subsystem, "block") == 0)
		udev->type = 'b';
	else if (strcmp(udev->subsystem, "net") == 0)
		udev->type = 'n';
	else if (strncmp(udev->devpath, "/block/", 7) == 0)
		udev->type = 'b';
	else if (strncmp(udev->devpath, "/class/net/", 11) == 0)
		udev->type = 'n';
	else if (strncmp(udev->devpath, "/class/", 7) == 0)
		udev->type = 'c';

	udev->mode = 0660;
	strcpy(udev->owner, "root");
	strcpy(udev->group, "root");
}

int kernel_release_satisfactory(int version, int patchlevel, int sublevel)
{
	static int kversion = 0;
	static int kpatchlevel;
	static int ksublevel;

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
	char p[NAME_SIZE];
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
	while (isspace(*string))
		++string;
	if (*string == '"')
		++string;
	else
		return -ENODEV;

	temp = strsep(&string, "\"");
	if (!string || *temp == '\0')
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
	int len;

	len = strlen(path);
	if (len > 0 && path[len-1] == '/')
		path[len-1] = '\0';
}

struct files {
	struct list_head list;
	char name[NAME_SIZE];
};

/* sort files in lexical order */
static int file_list_insert(char *filename, struct list_head *file_list)
{
	struct files *loop_file;
	struct files *new_file;

	list_for_each_entry(loop_file, file_list, list) {
		if (strcmp(loop_file->name, filename) > 0) {
			break;
		}
	}

	new_file = malloc(sizeof(struct files));
	if (new_file == NULL) {
		dbg("error malloc");
		return -ENOMEM;
	}

	strfieldcpy(new_file->name, filename);
	list_add_tail(&new_file->list, &loop_file->list);
	return 0;
}

/* calls function for every file found in specified directory */
int call_foreach_file(file_fnct_t fnct, const char *dirname,
		      const char *suffix, void *data)
{
	struct dirent *ent;
	DIR *dir;
	char *ext;
	struct files *loop_file;
	struct files *tmp_file;
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
		file_list_insert(ent->d_name, &file_list);
	}

	/* call function for every file in the list */
	list_for_each_entry_safe(loop_file, tmp_file, &file_list, list) {
		char filename[NAME_SIZE];

		snprintf(filename, NAME_SIZE, "%s/%s", dirname, loop_file->name);
		filename[NAME_SIZE-1] = '\0';

		fnct(filename, data);

		list_del(&loop_file->list);
		free(loop_file);
	}

	closedir(dir);
	return 0;
}
