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
#include <dirent.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "udev.h"
#include "logging.h"
#include "udev_lib.h"
#include "list.h"


char *get_action(void)
{
	char *action;

	action = getenv("ACTION");
	if (action != NULL && strlen(action) > ACTION_SIZE)
		action[ACTION_SIZE-1] = '\0';

	return action;
}

char *get_devpath(void)
{
	char *devpath;

	devpath = getenv("DEVPATH");
	if (devpath != NULL && strlen(devpath) > DEVPATH_SIZE)
		devpath[DEVPATH_SIZE-1] = '\0';

	return devpath;
}

char *get_devname(void)
{
	char *devname;

	devname = getenv("DEVNAME");
	if (devname != NULL && strlen(devname) > NAME_SIZE)
		devname[NAME_SIZE-1] = '\0';

	return devname;
}

char *get_seqnum(void)
{
	char *seqnum;

	seqnum = getenv("SEQNUM");

	return seqnum;
}

char *get_subsystem(char *subsystem)
{
	if (subsystem != NULL && strlen(subsystem) > SUBSYSTEM_SIZE)
		subsystem[SUBSYSTEM_SIZE-1] = '\0';

	return subsystem;
}

#define BLOCK_PATH		"/block/"
#define CLASS_PATH		"/class/"
#define NET_PATH		"/class/net/"

char get_device_type(const char *path, const char *subsystem)
{
	if (strcmp(subsystem, "block") == 0)
		return 'b';

	if (strcmp(subsystem, "net") == 0)
		return 'n';

	if (strncmp(path, BLOCK_PATH, strlen(BLOCK_PATH)) == 0 &&
	    strlen(path) > strlen(BLOCK_PATH))
		return 'b';

	if (strncmp(path, NET_PATH, strlen(NET_PATH)) == 0 &&
	    strlen(path) > strlen(NET_PATH))
		return 'n';

	if (strncmp(path, CLASS_PATH, strlen(CLASS_PATH)) == 0 &&
	    strlen(path) > strlen(CLASS_PATH))
		return 'c';

	return '\0';
}

void udev_set_values(struct udevice *udev, const char* devpath, const char *subsystem)
{
	memset(udev, 0x00, sizeof(struct udevice));
	strfieldcpy(udev->devpath, devpath);
	strfieldcpy(udev->subsystem, subsystem);
	udev->type = get_device_type(devpath, subsystem);
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

size_t buf_get_line(char *buf, size_t buflen, size_t cur)
{
	size_t count = 0;

	for (count = cur; count < buflen && buf[count] != '\n'; count++);

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
int call_foreach_file(int fnct(char *f) , char *dirname, char *suffix)
{
	struct dirent *ent;
	DIR *dir;
	char *ext;
	char file[NAME_SIZE];
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
		snprintf(file, NAME_SIZE-1, "%s/%s", dirname, loop_file->name);
		file[NAME_SIZE-1] = '\0';

		fnct(file);

		list_del(&loop_file->list);
		free(loop_file);
	}

	closedir(dir);
	return 0;
}

/* Set the FD_CLOEXEC  flag of desc if value is nonzero,
   or clear the flag if value is 0.
   Return 0 on success, or -1 on error with errno  set. */ 
	
int set_cloexec_flag (int desc, int value)
{
	int oldflags = fcntl (desc, F_GETFD, 0);
	/* If reading the flags failed, return error indication now. */
	if (oldflags < 0)
		return oldflags;
	/* Set just the flag we want to set. */
	if (value != 0)
		oldflags |= FD_CLOEXEC;
	else
		oldflags &= ~FD_CLOEXEC;
	/* Store modified flag word in the descriptor. */
	return fcntl (desc, F_SETFD, oldflags);
}
