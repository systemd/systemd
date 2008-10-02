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

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <unistd.h>

#include "udev.h"

#ifndef USE_SELINUX
void selinux_init(struct udev *udev) {}
void selinux_exit(struct udev *udev) {}
void udev_selinux_lsetfilecon(struct udev *udev, const char *file, unsigned int mode) {}
void udev_selinux_setfscreatecon(struct udev *udev, const char *file, unsigned int mode) {}
void udev_selinux_resetfscreatecon(struct udev *udev) {}
#else
#include <selinux/selinux.h>

static int selinux_enabled;
security_context_t selinux_prev_scontext;

void selinux_init(struct udev *udev)
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

void selinux_exit(struct udev *udev)
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
#endif
