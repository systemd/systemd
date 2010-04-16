/*
 * firmware - Load firmware device
 *
 * Copyright (C) 2009 Piter Punk <piterpunk@slackware.com>
 * Copyright (C) 2009 Kay Sievers <kay.sievers@vrfy.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details:*
 */

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <getopt.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include "libudev-private.h"

static bool set_loading(struct udev *udev, char *loadpath, const char *state)
{
	FILE *ldfile;

	ldfile = fopen(loadpath, "w");
	if (ldfile == NULL) {
		err(udev, "error: can not open '%s'\n", loadpath);
		return false;
	};
	fprintf(ldfile, "%s\n", state);
	fclose(ldfile);
	return true;
}

static bool copy_firmware(struct udev *udev, const char *source, const char *target, size_t size)
{
	char *buf;
	FILE *fsource, *ftarget;
	bool ret = false;

	buf = malloc(size);
	if (buf == NULL) {
		err(udev,"No memory available to load firmware file");
		return false;
	}

	fsource = fopen(source, "r");
	if (fsource == NULL)
		goto exit;
	ftarget = fopen(target, "w");
	if (ftarget == NULL)
		goto exit;
	if (fread(buf, size, 1, fsource) != 1)
		goto exit;
	if (fwrite(buf, size, 1, ftarget) == 1)
		ret = true;
exit:
	if (ftarget != NULL)
		fclose(ftarget);
	if (fsource != NULL)
		fclose(fsource);
	free(buf);
	return ret;
}

int main(int argc, char **argv)
{
	static const struct option options[] = {
		{ "firmware", required_argument, NULL, 'f' },
		{ "devpath", required_argument, NULL, 'p' },
		{ "help", no_argument, NULL, 'h' },
		{}
	};
	static const char *searchpath[] = { FIRMWARE_PATH };
	char fwencpath[UTIL_PATH_SIZE];
	char misspath[UTIL_PATH_SIZE];
	char loadpath[UTIL_PATH_SIZE];
	char datapath[UTIL_PATH_SIZE];
	char fwpath[UTIL_PATH_SIZE];
	char *devpath = NULL;
	char *firmware = NULL;
	FILE *fwfile;
	struct utsname kernel;
	struct stat statbuf;
	struct udev *udev = NULL;
	unsigned int i;
	int rc = 0;

	udev_log_init("firmware");

	for (;;) {
		int option;

		option = getopt_long(argc, argv, "f:p:h", options, NULL);
		if (option == -1)
			break;

		switch (option) {
		case 'f':
			firmware = optarg;
			break;
		case 'p':
			devpath = optarg;
			break;
		case 'h':
			printf("Usage: firmware --firmware=<fwfile> --devpath=<path> [--help]\n\n");
		default:
			rc = 1;
			goto exit;
		}
	}

	if (devpath == NULL || firmware == NULL) {
		fprintf(stderr, "firmware or devpath parameter missing\n\n");
		rc = 1;
		goto exit;
	}

	udev = udev_new();
	if (udev == NULL) {
		rc = 1;
		goto exit;
	};

	/* lookup firmware file */
	uname(&kernel);
	for (i = 0; i < ARRAY_SIZE(searchpath); i++) {
		util_strscpyl(fwpath, sizeof(fwpath), searchpath[i], kernel.release, "/", firmware, NULL);
		dbg(udev, "trying %s\n", fwpath);
		fwfile = fopen(fwpath, "r");
		if (fwfile != NULL)
			break; 

		util_strscpyl(fwpath, sizeof(fwpath), searchpath[i], firmware, NULL);
		dbg(udev, "trying %s\n", fwpath);
		fwfile = fopen(fwpath, "r");
		if (fwfile != NULL)
			break;
	}

	util_path_encode(firmware, fwencpath, sizeof(fwencpath));
	util_strscpyl(misspath, sizeof(misspath), udev_get_dev_path(udev), "/.udev/firmware-missing/", fwencpath, NULL);
	util_strscpyl(loadpath, sizeof(loadpath), udev_get_sys_path(udev), devpath, "/loading", NULL);

	if (fwfile == NULL) {
		int err;

		/* This link indicates the missing firmware file and the associated device */
		info(udev, "did not find firmware file '%s'\n", firmware);
		do {
			err = util_create_path(udev, misspath);
			if (err != 0 && err != -ENOENT)
				break;
			udev_selinux_setfscreatecon(udev, misspath, S_IFLNK);
			err = symlink(devpath, misspath);
			if (err != 0)
				err = -errno;
			udev_selinux_resetfscreatecon(udev);
		} while (err == -ENOENT);
		rc = 2;
		set_loading(udev, loadpath, "-1");
		goto exit;
	}

	if (stat(fwpath, &statbuf) < 0 || statbuf.st_size == 0) {
		rc = 3;
		goto exit;
	}
	if (unlink(misspath) == 0)
		util_delete_path(udev, misspath);

	if (!set_loading(udev, loadpath, "1"))
		goto exit;

	util_strscpyl(datapath, sizeof(datapath), udev_get_sys_path(udev), devpath, "/data", NULL);
	if (!copy_firmware(udev, fwpath, datapath, statbuf.st_size)) {
		err(udev, "error sending firmware '%s' to device\n", firmware);
		set_loading(udev, loadpath, "-1");
		rc = 4;
		goto exit;
	};

	set_loading(udev, loadpath, "0");
exit:
	udev_unref(udev);
	udev_log_close();
	return rc;
}
