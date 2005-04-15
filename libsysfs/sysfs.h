/*
 * sysfs.h
 *
 * Internal Header Definitions for libsysfs
 *
 * Copyright (C) IBM Corp. 2003-2005
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 */
#ifndef _SYSFS_H_
#define _SYSFS_H_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#define safestrcpy(to, from)	strncpy(to, from, sizeof(to)-1)
#define safestrcat(to, from)	strncat(to, from, sizeof(to) - strlen(to)-1)

#define safestrcpymax(to, from, max) \
do { \
	to[max-1] = '\0'; \
	strncpy(to, from, max-1); \
} while (0)

#define safestrcatmax(to, from, max) \
do { \
	to[max-1] = '\0'; \
	strncat(to, from, max - strlen(to)-1); \
} while (0)

extern struct sysfs_attribute *get_attribute(void *dev, const char *name);
extern struct dlist *read_dir_subdirs(const char *path);
extern struct dlist *read_dir_links(const char *path);
extern struct dlist *get_attributes_list(void *dev);

/* Debugging */
#ifdef DEBUG
#include "../logging.h"
#define dprintf(format, arg...) dbg(format, ## arg)
#else
#define dprintf(format, arg...) do { } while (0)
#endif

#endif /* _SYSFS_H_ */
