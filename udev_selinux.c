/*
 * Copyright (C) 2004 Daniel Walsh
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
 *	51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <limits.h>
#include <libgen.h>
#include <errno.h>
#include <selinux/selinux.h>

#include "udev.h"
#include "udev_selinux.h"

static security_context_t prev_scontext = NULL;

static int is_selinux_running(void)
{
	static int selinux_enabled = -1;

	if (selinux_enabled == -1) 
		selinux_enabled = (is_selinux_enabled() > 0);

	dbg("selinux=%i", selinux_enabled);
	return selinux_enabled;
}

static char *get_media(const char *devname, int mode)
{
	FILE *fp;
	char procfile[PATH_MAX];
	char mediabuf[256];
	int size;
	char *media = NULL;

	if (!(mode & S_IFBLK))
		return NULL;

	snprintf(procfile, PATH_MAX, "/proc/ide/%s/media", devname);
	procfile[PATH_MAX-1] = '\0';

	fp = fopen(procfile, "r");
	if (!fp)
		goto out;

	if (fgets(mediabuf, sizeof(mediabuf), fp) == NULL)
		goto close_out;

	size = strlen(mediabuf);
	while (size-- > 0) {
		if (isspace(mediabuf[size])) {
			mediabuf[size] = '\0';
		} else {
			break;
		}
	}

	media = strdup(mediabuf);
	info("selinux_get_media(%s)='%s'\n", devname, media);

close_out:
	fclose(fp);
out:
	return media;
}

void selinux_setfilecon(const char *file, const char *devname, unsigned int mode)
{
	if (is_selinux_running()) {
		security_context_t scontext = NULL;
		char *media;
		int ret = -1;

		if (devname) {
			media = get_media(devname, mode);
			if (media) {
				ret = matchmediacon(media, &scontext);
				free(media);
			}
		}

		if (ret < 0)
			if (matchpathcon(file, mode, &scontext) < 0) {
				err("matchpathcon(%s) failed\n", file);
				return;
			} 

		if (lsetfilecon(file, scontext) < 0)
			err("setfilecon %s failed: %s", file, strerror(errno));

		freecon(scontext);
	}
}

void selinux_setfscreatecon(const char *file, const char *devname, unsigned int mode)
{
	if (is_selinux_running()) {
		security_context_t scontext = NULL;
		char *media;
		int ret = -1;

		media = get_media(devname, mode);
		if (media) {
			ret = matchmediacon(media, &scontext);
			free(media);
		}

		if (ret < 0)
			if (matchpathcon(file, mode, &scontext) < 0) {
				err("matchpathcon(%s) failed\n", file);
				return;
			}

		if (setfscreatecon(scontext) < 0)
			err("setfscreatecon %s failed: %s", file, strerror(errno));

		freecon(scontext);
	}
}

void selinux_resetfscreatecon(void)
{
	if (is_selinux_running()) {
		if (setfscreatecon(prev_scontext) < 0)
			err("setfscreatecon failed: %s", strerror(errno));
	}
}

void selinux_init(void)
{
	/*
	 * record the present security context, for file-creation
	 * restoration creation purposes.
	 */
	if (is_selinux_running()) {
		matchpathcon_init_prefix(NULL, udev_root);
		if (getfscreatecon(&prev_scontext) < 0) {
			err("getfscreatecon failed\n");
			prev_scontext = NULL;
		}
	}
}

void selinux_exit(void)
{
	if (is_selinux_running() && prev_scontext) {
		freecon(prev_scontext);
		prev_scontext = NULL;
	}
}
