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


extern char *get_action(void);
extern char *get_devpath(void);
extern char *get_devname(void);
extern char *get_seqnum(void);
extern char *get_subsystem(char *subsystem);
extern char get_device_type(const char *path, const char *subsystem);
extern int file_map(const char *filename, char **buf, size_t *bufsize);
extern void file_unmap(char *buf, size_t bufsize);
extern size_t buf_get_line(char *buf, size_t buflen, size_t cur);
extern int  call_foreach_file(int fnct(char *f) , char *filename, char *extension);


#endif
