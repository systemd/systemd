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
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "libsysfs/sysfs/libsysfs.h"
#include "udev.h"
#include "udev_lib.h"


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

int file_map(const char *filename, char **buf, size_t *bufsize)
{
	struct stat stats;
	int fd;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		return -1;
	}

	if (fstat(fd, &stats) < 0) {
		return -1;
	}

	*buf = mmap(NULL, stats.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (*buf == MAP_FAILED) {
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

