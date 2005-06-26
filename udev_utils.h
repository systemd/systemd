/*
 * udev_lib - generic stuff used by udev
 *
 * Copyright (C) 2004 Kay Sievers <kay.sievers@vrfy.org>
 *
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

#ifndef _UDEV_LIB_H_
#define _UDEV_LIB_H_

#include "udev.h"

struct name_entry {
	struct list_head node;
	char name[PATH_SIZE];
};

extern int udev_init_device(struct udevice *udev, const char* devpath, const char *subsystem, const char *action);
extern void udev_cleanup_device(struct udevice *udev);

extern int kernel_release_satisfactory(unsigned int version, unsigned int patchlevel, unsigned int sublevel);
extern int create_path(const char *path);
extern int log_priority(const char *priority);
extern int string_is_true(const char *str);
extern int parse_get_pair(char **orig_string, char **left, char **right);
extern int unlink_secure(const char *filename);
extern int file_map(const char *filename, char **buf, size_t *bufsize);
extern void file_unmap(void *buf, size_t bufsize);
extern size_t buf_get_line(const char *buf, size_t buflen, size_t cur);
extern void remove_trailing_char(char *path, char c);
extern void replace_untrusted_chars(char *string);
extern int name_list_add(struct list_head *name_list, const char *name, int sort);
extern int name_list_key_add(struct list_head *name_list, const char *key, const char *value);
extern int add_matching_files(struct list_head *name_list, const char *dirname, const char *suffix);
extern int execute_program(const char *command, const char *subsystem,
			   char *result, size_t ressize, size_t *reslen);

#endif
