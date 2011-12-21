/*
 * probe disks for filesystems and partitions
 *
 * Copyright (C) 2011 Kay Sievers <kay.sievers@vrfy.org>
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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "udev.h"

static int builtin_kmod(struct udev_device *dev, const char *command, bool test)
{
	printf("soon we load a module here: '%s'\n", command);
	return EXIT_SUCCESS;
}

const struct udev_builtin udev_builtin_kmod = {
	.name = "kmod",
	.cmd = builtin_kmod,
	.help = "kernel module loader",
	.run_once = false,
};
