/*
 * load kernel modules
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

static char *kmod;

static int builtin_kmod(struct udev_device *dev, int argc, char *argv[], bool test)
{
	struct udev *udev = udev_device_get_udev(dev);

	if (argc < 3) {
		err(udev, "missing command + argument\n");
		return EXIT_FAILURE;
	}

	printf("soon we '%s' the module '%s' (%i) here\n", argv[1], argv[2], argc);
	printf("test: %s\n", kmod);
	return EXIT_SUCCESS;
}

static int builtin_kmod_load(struct udev *udev)
{
	info(udev, "load module index\n");
	asprintf(&kmod, "pid: %u", getpid());
	return 0;
}

static int builtin_kmod_unload(struct udev *udev)
{
	info(udev, "unload module index\n");
	free(kmod);
	return 0;
}

const struct udev_builtin udev_builtin_kmod = {
	.name = "kmod",
	.cmd = builtin_kmod,
	.load = builtin_kmod_load,
	.unload = builtin_kmod_unload,
	.help = "kernel module loader",
	.run_once = false,
};
