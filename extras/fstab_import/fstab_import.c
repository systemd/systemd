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

#include "../../udev.h"

static int debug;
static char root[PATH_SIZE] = "/dev";
static char **devices;

#ifdef USE_LOG
void log_message(int priority, const char *format, ...)
{
	va_list args;
	static int udev_log = -1;

	if (udev_log == -1) {
		const char *value;

		value = getenv("UDEV_LOG");
		if (value)
			udev_log = log_priority(value);
		else
			udev_log = LOG_ERR;

		if (debug && udev_log < LOG_INFO)
			udev_log = LOG_INFO;
	}

	if (priority > udev_log)
		return;

	va_start(args, format);
	if (debug) {
		fprintf(stderr, "[%d] ", (int) getpid());
		vfprintf(stderr, format, args);
	} else
		vsyslog(priority, format, args);
	va_end(args);
}
#endif

static int matches_device_list(const char *name)
{
	int i;

	for (i = 0; devices[i] != NULL; i++) {
		info("compare '%s' == '%s'\n", name, devices[i]);
		if (strcmp(devices[i], name) == 0)
			return 1;
	}
	return 0;
}

static void print_fstab_entry(struct mntent *mnt)
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
	static const struct option options[] = {
		{ "export", 0, NULL, 'x' },
		{ "root", 1, NULL, 'r' },
		{ "debug", 0, NULL, 'd' },
		{ "help", 0, NULL, 'h' },
		{}
	};

	FILE *fp;
	struct mntent *mnt;
	int rc = 0;

	logging_init("fstab_id");

	while (1) {
		int option;

		option = getopt_long(argc, argv, "dr:xh", options, NULL);
		if (option == -1)
			break;

		switch (option) {
		case 'r':
			strlcpy(root, optarg, sizeof(root));
			break;
		case 'd':
			debug = 1;
			break;
		case 'h':
			printf("Usage: fstab_id [OPTIONS] name [...]\n"
			       "  --export        print environment keys\n"
			       "  --root          device node root (default /dev)\n"
			       "  --debug         debug to stderr\n"
			       "  --help          print this help text\n\n");
		default:
			rc = 1;
			goto exit;
		}
	}

	devices = &argv[optind];
	if (devices[0] == NULL) {
		fprintf(stderr, "error: missing device(s) to match\n");
		rc = 2;
		goto exit;
	}

	fp = setmntent ("/etc/fstab", "r");
	if (fp == NULL) {
		fprintf(stderr, "error: opening fstab: %s\n", strerror(errno));
		rc = 2;
		goto exit;
	}

	while (1) {
		mnt = getmntent(fp);
		if (mnt == NULL)
			break;

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

				strlcpy(str, &label[1], sizeof(str));
				pos = strrchr(str, label[0]);
				if (pos == NULL)
					continue;
				pos[0] = '\0';
				label = str;
			}
			if (matches_device_list(str)) {
				print_fstab_entry(mnt);
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

				strlcpy(str, &uuid[1], sizeof(str));
				pos = strrchr(str, uuid[0]);
				if (pos == NULL)
					continue;
				pos[0] = '\0';
				uuid = str;
			}
			if (matches_device_list(str)) {
				print_fstab_entry(mnt);
				break;
			}
			continue;
		}

		/* only devices */
		if (strncmp(mnt->mnt_fsname, root, strlen(root)) != 0)
			continue;

		if (matches_device_list(&mnt->mnt_fsname[strlen(root)+1])) {
			print_fstab_entry(mnt);
			break;
		}
	}

	endmntent(fp);

exit:
	logging_close();
	return rc;
}
