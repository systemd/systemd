/*
 * sysfs.h
 *
 * Internal Header Definitions for libsysfs
 *
 * Copyright (C) IBM Corp. 2003
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
#include <mntent.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

/* external library functions */
extern int lstat(const char *file_name, struct stat *buf);
extern int readlink(const char *path, char *buf, size_t bufsize);
extern int getpagesize(void);
extern int isascii(int c);

/* Debugging */
#ifdef DEBUG
#define dprintf(format, arg...) fprintf(stderr, format, ## arg)
#else
#define dprintf(format, arg...) do { } while (0)
#endif

#endif /* _SYSFS_H_ */
