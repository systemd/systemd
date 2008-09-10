/*
 * libudev - interface to udev device information
 *
 * Copyright (C) 2008 Kay Sievers <kay.sievers@vrfy.org>
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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

#include "libudev.h"
#include "libudev-private.h"

static ssize_t get_sys_link(struct udev *udev, const char *slink, const char *devpath, char *subsystem, size_t size)
{
	char path[UTIL_PATH_SIZE];
	ssize_t len;
	const char *pos;

	util_strlcpy(path, udev_get_sys_path(udev), sizeof(path));
	util_strlcat(path, devpath, sizeof(path));
	util_strlcat(path, "/", sizeof(path));
	util_strlcat(path, slink, sizeof(path));
	len = readlink(path, path, sizeof(path));
	if (len < 0 || len >= (ssize_t) sizeof(path))
		return -1;
	path[len] = '\0';
	pos = strrchr(path, '/');
	if (pos == NULL)
		return -1;
	pos = &pos[1];
	return util_strlcpy(subsystem, pos, size);
}

ssize_t util_get_sys_subsystem(struct udev *udev, const char *devpath, char *subsystem, size_t size)
{
	return get_sys_link(udev, "subsystem", devpath, subsystem, size);
}

ssize_t util_get_sys_driver(struct udev *udev, const char *devpath, char *driver, size_t size)
{
	return get_sys_link(udev, "driver", devpath, driver, size);
}

int util_resolve_sys_link(struct udev *udev, char *devpath, size_t size)
{
	char link_path[UTIL_PATH_SIZE];
	char link_target[UTIL_PATH_SIZE];

	int len;
	int i;
	int back;

	util_strlcpy(link_path, udev_get_sys_path(udev), sizeof(link_path));
	util_strlcat(link_path, devpath, sizeof(link_path));
	len = readlink(link_path, link_target, sizeof(link_target));
	if (len <= 0)
		return -1;
	link_target[len] = '\0';
	dbg(udev, "path link '%s' points to '%s'\n", devpath, link_target);

	for (back = 0; strncmp(&link_target[back * 3], "../", 3) == 0; back++)
		;
	dbg(udev, "base '%s', tail '%s', back %i\n", devpath, &link_target[back * 3], back);
	for (i = 0; i <= back; i++) {
		char *pos = strrchr(devpath, '/');

		if (pos == NULL)
			return -1;
		pos[0] = '\0';
	}
	dbg(udev, "after moving back '%s'\n", devpath);
	util_strlcat(devpath, "/", size);
	util_strlcat(devpath, &link_target[back * 3], size);
	return 0;
}

struct util_name_entry *util_name_list_add(struct udev *udev, struct list_head *name_list,
					   const char *name, int sort)
{
	struct util_name_entry *name_loop;
	struct util_name_entry *name_new;

	/* avoid duplicate entries */
	list_for_each_entry(name_loop, name_list, node) {
		if (strcmp(name_loop->name, name) == 0) {
			dbg(udev, "'%s' is already in the list\n", name);
			return name_loop;
		}
	}

	if (sort) {
		list_for_each_entry(name_loop, name_list, node) {
			if (strcmp(name_loop->name, name) > 0)
				break;
		}
	}

	name_new = malloc(sizeof(struct util_name_entry));
	if (name_new == NULL)
		return NULL;
	memset(name_new, 0x00, sizeof(struct util_name_entry));
	name_new->name = strdup(name);
	if (name_new->name == NULL) {
		free(name_new);
		return NULL;
	}
	dbg(udev, "adding '%s'\n", name_new->name);
	list_add_tail(&name_new->node, &name_loop->node);
	return name_new;
}

void util_name_list_cleanup(struct udev *udev, struct list_head *name_list)
{
	struct util_name_entry *name_loop;
	struct util_name_entry *name_tmp;

	list_for_each_entry_safe(name_loop, name_tmp, name_list, node) {
		list_del(&name_loop->node);
		free(name_loop->name);
		free(name_loop);
	}
}

int util_log_priority(const char *priority)
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
	return 0;
}

size_t util_path_encode(char *s, size_t len)
{
	char t[(len * 3)+1];
	size_t i, j;

	t[0] = '\0';
	for (i = 0, j = 0; s[i] != '\0'; i++) {
		if (s[i] == '/') {
			memcpy(&t[j], "\\x2f", 4);
			j += 4;
		} else if (s[i] == '\\') {
			memcpy(&t[j], "\\x5c", 4);
			j += 4;
		} else {
			t[j] = s[i];
			j++;
		}
	}
	t[j] = '\0';
	strncpy(s, t, len);
	return j;
}

size_t util_path_decode(char *s)
{
	size_t i, j;

	for (i = 0, j = 0; s[i] != '\0'; j++) {
		if (memcmp(&s[i], "\\x2f", 4) == 0) {
			s[j] = '/';
			i += 4;
		}else if (memcmp(&s[i], "\\x5c", 4) == 0) {
			s[j] = '\\';
			i += 4;
		} else {
			s[j] = s[i];
			i++;
		}
	}
	s[j] = '\0';
	return j;
}

void util_remove_trailing_chars(char *path, char c)
{
	size_t len;

	if (path == NULL)
		return;
	len = strlen(path);
	while (len > 0 && path[len-1] == c)
		path[--len] = '\0';
}

size_t util_strlcpy(char *dst, const char *src, size_t size)
{
	size_t bytes = 0;
	char *q = dst;
	const char *p = src;
	char ch;

	while ((ch = *p++)) {
		if (bytes+1 < size)
			*q++ = ch;
		bytes++;
	}

	/* If size == 0 there is no space for a final null... */
	if (size)
		*q = '\0';
	return bytes;
}

size_t util_strlcat(char *dst, const char *src, size_t size)
{
	size_t bytes = 0;
	char *q = dst;
	const char *p = src;
	char ch;

	while (bytes < size && *q) {
		q++;
		bytes++;
	}
	if (bytes == size)
		return (bytes + strlen(src));

	while ((ch = *p++)) {
		if (bytes+1 < size)
		*q++ = ch;
		bytes++;
	}

	*q = '\0';
	return bytes;
}
