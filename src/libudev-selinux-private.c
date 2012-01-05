/*
 * libudev - interface to udev device information
 *
 * Copyright (C) 2008 Kay Sievers <kay.sievers@vrfy.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <unistd.h>
#include <selinux/selinux.h>

#include "libudev.h"
#include "libudev-private.h"

static int selinux_enabled;
security_context_t selinux_prev_scontext;

void udev_selinux_init(struct udev *udev)
{
	/* record the present security context */
	selinux_enabled = (is_selinux_enabled() > 0);
	info(udev, "selinux=%i\n", selinux_enabled);
	if (!selinux_enabled)
		return;
	matchpathcon_init_prefix(NULL, udev_get_dev_path(udev));
	if (getfscreatecon(&selinux_prev_scontext) < 0) {
		err(udev, "getfscreatecon failed\n");
		selinux_prev_scontext = NULL;
	}
}

void udev_selinux_exit(struct udev *udev)
{
	if (!selinux_enabled)
		return;
	freecon(selinux_prev_scontext);
	selinux_prev_scontext = NULL;
}

void udev_selinux_lsetfilecon(struct udev *udev, const char *file, unsigned int mode)
{
	security_context_t scontext = NULL;

	if (!selinux_enabled)
		return;
	if (matchpathcon(file, mode, &scontext) < 0) {
		err(udev, "matchpathcon(%s) failed\n", file);
		return;
	}
	if (lsetfilecon(file, scontext) < 0)
		err(udev, "setfilecon %s failed: %m\n", file);
	freecon(scontext);
}

void udev_selinux_setfscreatecon(struct udev *udev, const char *file, unsigned int mode)
{
	security_context_t scontext = NULL;

	if (!selinux_enabled)
		return;

	if (matchpathcon(file, mode, &scontext) < 0) {
		err(udev, "matchpathcon(%s) failed\n", file);
		return;
	}
	if (setfscreatecon(scontext) < 0)
		err(udev, "setfscreatecon %s failed: %m\n", file);
	freecon(scontext);
}

void udev_selinux_resetfscreatecon(struct udev *udev)
{
	if (!selinux_enabled)
		return;
	if (setfscreatecon(selinux_prev_scontext) < 0)
		err(udev, "setfscreatecon failed: %m\n");
}

void udev_selinux_setfscreateconat(struct udev *udev, int dfd, const char *file, unsigned int mode)
{
	char filename[UTIL_PATH_SIZE];

	if (!selinux_enabled)
		return;

	/* resolve relative filename */
	if (file[0] != '/') {
		char procfd[UTIL_PATH_SIZE];
		char target[UTIL_PATH_SIZE];
		ssize_t len;

		snprintf(procfd, sizeof(procfd), "/proc/%u/fd/%u", getpid(), dfd);
		len = readlink(procfd, target, sizeof(target));
		if (len <= 0 || len == sizeof(target))
			return;
		target[len] = '\0';

		util_strscpyl(filename, sizeof(filename), target, "/", file, NULL);
		file = filename;
	}
	udev_selinux_setfscreatecon(udev, file, mode);
}
