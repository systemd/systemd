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

#define strfieldcpy(to, from) \
do { \
	to[sizeof(to)-1] = '\0'; \
	strncpy(to, from, sizeof(to)-1); \
} while (0)

#define strfieldcat(to, from) \
do { \
	to[sizeof(to)-1] = '\0'; \
	strncat(to, from, sizeof(to) - strlen(to)-1); \
} while (0)

#define strfieldcpymax(to, from, maxsize) \
do { \
	to[maxsize-1] = '\0'; \
	strncpy(to, from, maxsize-1); \
} while (0)

#define strfieldcatmax(to, from, maxsize) \
do { \
	to[maxsize-1] = '\0'; \
	strncat(to, from, maxsize - strlen(to)-1); \
} while (0)

#define strintcat(to, i) \
do { \
	to[sizeof(to)-1] = '\0'; \
	snprintf((to) + strlen(to), sizeof(to) - strlen(to)-1, "%u", i); \
} while (0)

#define strintcatmax(to, i, maxsize) \
do { \
	to[maxsize-1] = '\0'; \
	snprintf((to) + strlen(to), maxsize - strlen(to)-1, "%u", i); \
} while (0)

#define foreach_strpart(str, separator, pos, len) \
	for(pos = str, len = 0; \
	    (pos) < ((str) + strlen(str)); \
	    pos = pos + len + strspn(pos, separator), len = strcspn(pos, separator)) \
		if (len > 0)

#ifdef asmlinkage
# undef asmlinkage
#endif
#ifdef __i386__
# define asmlinkage	__attribute__((regparm(0)))
#endif
#ifndef asmlinkage
# define asmlinkage	/* nothing */
#endif

extern void udev_init_device(struct udevice *udev, const char* devpath, const char *subsystem);
extern int kernel_release_satisfactory(unsigned int version, unsigned int patchlevel, unsigned int sublevel);
extern int create_path(const char *path);
extern int parse_get_pair(char **orig_string, char **left, char **right);
extern int file_map(const char *filename, char **buf, size_t *bufsize);
extern void file_unmap(char *buf, size_t bufsize);
extern size_t buf_get_line(const char *buf, size_t buflen, size_t cur);
extern void no_trailing_slash(char *path);
typedef int (*file_fnct_t)(const char *filename, void *data);
extern int  call_foreach_file(file_fnct_t fnct, const char *dirname,
			      const char *suffix, void *data);

#endif
