/*
 * find matching entry in fstab and export it
 *
 * Copyright (C) 2008 Kay Sievers <kay.sievers@vrfy.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <mntent.h>
#include <sys/stat.h>

#include "libudev.h"
#include "libudev-private.h"

static int debug;

static void log_fn(struct udev *udev, int priority,
		   const char *file, int line, const char *fn,
		   const char *format, va_list args)
{
	if (debug) {
		fprintf(stderr, "%s: ", fn);
		vfprintf(stderr, format, args);
	} else {
		vsyslog(priority, format, args);
	}
}

static int matches_device_list(struct udev *udev, char **devices, const char *name)
{
	int i;

	for (i = 0; devices[i] != NULL; i++) {
		info(udev, "compare '%s' == '%s'\n", name, devices[i]);
		if (strcmp(devices[i], name) == 0)
			return 1;
	}
	return 0;
}

static void print_fstab_entry(struct udev *udev, struct mntent *mnt)
{
	printf("FSTAB_NAME=%s\n", mnt->mnt_fsname);
	printf("FSTAB_DIR=%s\n", mnt->mnt_dir);
	printf("FSTAB_TYPE=%s\n", mnt->mnt_type);
	printf("FSTAB_OPTS=%s\n", mnt->mnt_opts);
	printf("FSTAB_FREQ=%d\n", mnt->mnt_freq);
	printf("FSTAB_PASSNO=%d\n", mnt->mnt_passno);
}

int main(int argc, char *argv[])
{
	struct udev *udev;
	static const struct option options[] = {
		{ "export", no_argument, NULL, 'x' },
		{ "debug", no_argument, NULL, 'd' },
		{ "help", no_argument, NULL, 'h' },
		{}
	};
	char **devices;
	FILE *fp;
	struct mntent *mnt;
	int rc = 1;

	udev = udev_new();
	if (udev == NULL)
		goto exit;

	udev_log_init("fstab_id");
	udev_set_log_fn(udev, log_fn);

	while (1) {
		int option;

		option = getopt_long(argc, argv, "dxh", options, NULL);
		if (option == -1)
			break;

		switch (option) {
		case 'd':
			debug = 1;
			if (udev_get_log_priority(udev) < LOG_INFO)
				udev_set_log_priority(udev, LOG_INFO);
			break;
		case 'h':
			printf("Usage: fstab_id [OPTIONS] name [...]\n"
			       "  --export        print environment keys\n"
			       "  --debug         debug to stderr\n"
			       "  --help          print this help text\n\n");
			goto exit;
		case 'x':
			break;
		default:
			rc = 2;
			goto exit;
		}
	}

	devices = &argv[optind];
	if (devices[0] == NULL) {
		fprintf(stderr, "error: missing device(s) to match\n");
		rc = 3;
		goto exit;
	}

	fp = setmntent ("/etc/fstab", "r");
	if (fp == NULL) {
		fprintf(stderr, "error: opening fstab: %s\n", strerror(errno));
		rc = 4;
		goto exit;
	}

	while (1) {
		mnt = getmntent(fp);
		if (mnt == NULL)
			break;

		info(udev, "found '%s'@'%s'\n", mnt->mnt_fsname, mnt->mnt_dir);

		/* skip root device */
		if (strcmp(mnt->mnt_dir, "/") == 0)
			continue;

		/* match LABEL */
		if (strncmp(mnt->mnt_fsname, "LABEL=", 6) == 0) {
			const char *label;
			char str[256];

			label = &mnt->mnt_fsname[6];
			if (label[0] == '"' || label[0] == '\'') {
				char *pos;

				util_strscpy(str, sizeof(str), &label[1]);
				pos = strrchr(str, label[0]);
				if (pos == NULL)
					continue;
				pos[0] = '\0';
				label = str;
			}
			if (matches_device_list(udev, devices, label)) {
				print_fstab_entry(udev, mnt);
				rc = 0;
				break;
			}
			continue;
		}

		/* match UUID */
		if (strncmp(mnt->mnt_fsname, "UUID=", 5) == 0) {
			const char *uuid;
			char str[256];

			uuid = &mnt->mnt_fsname[5];
			if (uuid[0] == '"' || uuid[0] == '\'') {
				char *pos;

				util_strscpy(str, sizeof(str), &uuid[1]);
				pos = strrchr(str, uuid[0]);
				if (pos == NULL)
					continue;
				pos[0] = '\0';
				uuid = str;
			}
			if (matches_device_list(udev, devices, uuid)) {
				print_fstab_entry(udev, mnt);
				rc = 0;
				break;
			}
			continue;
		}

		/* only devices */
		if (strncmp(mnt->mnt_fsname, udev_get_dev_path(udev), strlen(udev_get_dev_path(udev))) != 0)
			continue;

		if (matches_device_list(udev, devices, &mnt->mnt_fsname[strlen(udev_get_dev_path(udev))+1])) {
			print_fstab_entry(udev, mnt);
			rc = 0;
			break;
		}
	}
	endmntent(fp);

exit:
	udev_unref(udev);
	udev_log_close();
	return rc;
}
