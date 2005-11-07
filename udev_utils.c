/*
 * udev_utils.c - generic stuff used by udev
 *
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
#include <sys/utsname.h>

#include "udev_libc_wrapper.h"
#include "udev.h"
#include "logging.h"
#include "udev_utils.h"
#include "list.h"


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

void name_list_cleanup(struct list_head *name_list)
{
	struct name_entry *name_loop;
	struct name_entry *temp_loop;

	list_for_each_entry_safe(name_loop, temp_loop, name_list, node) {
		list_del(&name_loop->node);
		free(name_loop);
	}
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
		err("unable to open '%s': %s", dirname, strerror(errno));
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
