/*
 * edd_id - naming of BIOS disk devices via EDD
 *
 * Copyright (C) 2005 John Hull <John_Hull@Dell.com>
 * Copyright (C) 2005 Kay Sievers <kay.sievers@vrfy.org>
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
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
#include <dirent.h>
#include <stdint.h>

#include "../../udev.h"

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
	}

	if (priority > udev_log)
		return;

	va_start(args, format);
	vsyslog(priority, format, args);
	va_end(args);
}
#endif

int main(int argc, char *argv[])
{
	const char *node = NULL;
	int i;
	int export = 0;
	uint32_t disk_id;
	uint16_t mbr_valid;
	struct dirent *dent;
	int disk_fd;
	int sysfs_fd;
	DIR *dir = NULL;
	int rc = 1;
	char match[NAME_MAX] = "";

	logging_init("edd_id");

	for (i = 1 ; i < argc; i++) {
		char *arg = argv[i];

		if (strcmp(arg, "--export") == 0) {
			export = 1;
		} else
			node = arg;
	}
	if (node == NULL) {
		err("no node specified");
		fprintf(stderr, "no node specified\n");
		goto exit;
	}

	/* check for kernel support */
	dir = opendir("/sys/firmware/edd");
	if (dir == NULL) {
		info("no kernel EDD support");
		fprintf(stderr, "no kernel EDD support\n");
		rc = 2;
		goto exit;
	}

	disk_fd = open(node, O_RDONLY);
	if (disk_fd < 0) {
		info("unable to open '%s'", node);
		fprintf(stderr, "unable to open '%s'\n", node);
		rc = 3;
		goto closedir;
	}

	/* check for valid MBR signature */
	if (lseek(disk_fd, 510, SEEK_SET) < 0) {
		info("seek to MBR validity failed '%s'", node);
		rc = 4;
		goto close;
	}
	if (read(disk_fd, &mbr_valid, sizeof(mbr_valid)) != sizeof(mbr_valid)) {
		info("read MBR validity failed '%s'", node);
		rc = 5;
		goto close;
	}
	if (mbr_valid != 0xAA55) {
		fprintf(stderr, "no valid MBR signature '%s'\n", node);
		info("no valid MBR signature '%s'", node);
		rc=6;
		goto close;
	}

	/* read EDD signature */
	if (lseek(disk_fd, 440, SEEK_SET) < 0) {
		info("seek to signature failed '%s'", node);
		rc = 7;
		goto close;
	}
	if (read(disk_fd, &disk_id, sizeof(disk_id)) != sizeof(disk_id)) {
		info("read signature failed '%s'", node);
		rc = 8;
		goto close;
	}
	/* all zero is invalid */
	info("read id 0x%08x from '%s'", disk_id, node);
	if (disk_id == 0) {
		fprintf(stderr, "no EDD signature '%s'\n", node);
		info("'%s' signature is zero", node);
		rc = 9;
		goto close;
	}

	/* lookup signature in sysfs to determine the name */
	for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
		char file[PATH_SIZE];
		char sysfs_id_buf[256];
		uint32_t sysfs_id;
		ssize_t size;

		if (dent->d_name[0] == '.')
			continue;

		snprintf(file, sizeof(file), "/sys/firmware/edd/%s/mbr_signature", dent->d_name);
		file[sizeof(file)-1] = '\0';

		sysfs_fd = open(file, O_RDONLY);
		if (sysfs_fd < 0) {
			info("unable to open sysfs '%s'", file);
			continue;
		}

		size = read(sysfs_fd, sysfs_id_buf, sizeof(sysfs_id_buf)-1);
		close(sysfs_fd);
		if (size <= 0) {
			info("read sysfs '%s' failed", file);
			continue;
		}
		sysfs_id_buf[size] = '\0';
		info("read '%s' from '%s'", sysfs_id_buf, file);
		sysfs_id = strtoul(sysfs_id_buf, NULL, 16);

		/* look for matching value, that appears only once */
		if (disk_id == sysfs_id) {
			if (match[0] == '\0') {
				/* store id */
				strlcpy(match, dent->d_name, sizeof(match));
			} else {
				/* error, same signature for another device */
				info("'%s' does not have a unique signature", node);
				fprintf(stderr, "'%s' does not have a unique signature\n", node);
				rc = 10;
				goto exit;
			}
		}
	}

	if (match[0] != '\0') {
		if (export)
			printf("ID_EDD=%s\n", match);
		else
			printf("%s\n", match);
		rc = 0;
	}

close:
	close(disk_fd);
closedir:
	closedir(dir);
exit:
	logging_close();
	return rc;
}
