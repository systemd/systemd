/*
 * Copyright (C) 2009 Lennart Poettering <lennart@poettering.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details:
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <ctype.h>
#include <stdlib.h>

#include <libudev.h>

#if defined(BUILD_FOR_USB)
# define DATABASE USB_DATABASE
# define SUBSYSTEM "usb"
# define DEVTYPE "usb_device"
# define VENDOR_ATTR "idVendor"
# define PRODUCT_ATTR "idProduct"
#elif defined(BUILD_FOR_PCI)
# define DATABASE PCI_DATABASE
# define SUBSYSTEM "pci"
# define DEVTYPE NULL
# define VENDOR_ATTR "vendor"
# define PRODUCT_ATTR "device"
#else
# error "Are you havin' a laugh?"
#endif

static int get_id_attr(
	struct udev_device *parent,
	const char *name,
	uint16_t *value) {

	const char *t;
	unsigned u;

	if (!(t = udev_device_get_sysattr_value(parent, name))) {
		fprintf(stderr, "%s lacks %s.\n", udev_device_get_syspath(parent), name);
		return -1;
	}

	if (!strncmp(t, "0x", 2))
		t += 2;

	if (sscanf(t, "%04x", &u) != 1 || u > 0xFFFFU) {
		fprintf(stderr, "Failed to parse %s on %s.\n", name, udev_device_get_syspath(parent));
		return -1;
	}

	*value = (uint16_t) u;
	return 0;
}

static int get_vid_pid(
	struct udev_device *parent,
	uint16_t *vid,
	uint16_t *pid) {

	if (get_id_attr(parent, VENDOR_ATTR, vid) < 0)
		return -1;
	else if (*vid <= 0) {
		fprintf(stderr, "Invalid vendor id.\n");
		return -1;
	}

	if (get_id_attr(parent, PRODUCT_ATTR, pid) < 0)
		return -1;

	return 0;
}

static void rstrip(char *n) {
	size_t i;

	for (i = strlen(n); i > 0 && isspace(n[i-1]); i--)
		n[i-1] = 0;
}

#define HEXCHARS "0123456789abcdefABCDEF"
#define WHITESPACE " \t\n\r"

static int lookup_vid_pid(
	uint16_t vid,
	uint16_t pid,
	char **vendor,
	char **product) {

	FILE *f;
	int ret = -1;
	int found_vendor = 0;
	char *line = NULL;

	*vendor = *product = NULL;

	if (!(f = fopen(DATABASE, "r"))) {
		fprintf(stderr, "Failed to open database file "DATABASE": %s\n", strerror(errno));
		return -1;
	}

	for (;;) {
		size_t n;

		if (line) {
			free(line);
			line = NULL;
		}

		if (getline(&line, &n, f) < 0)
			break;

		rstrip(line);

		if (line[0] == '#' || line[0] == 0)
			continue;

		if (strspn(line, HEXCHARS) == 4) {
			unsigned u;

			if (found_vendor)
				break;

			if (sscanf(line, "%04x", &u) == 1 && u == vid) {
				char *t;

				t = line+4;
				t += strspn(t, WHITESPACE);

				if (!(*vendor = strdup(t))) {
					fprintf(stderr, "Out of memory.\n");
					goto finish;
				}

				found_vendor = 1;
			}

			continue;
		}

		if (found_vendor && line[0] == '\t' && strspn(line+1, HEXCHARS) == 4) {
			unsigned u;

			if (sscanf(line+1, "%04x", &u) == 1 && u == pid) {
				char *t;

				t = line+5;
				t += strspn(t, WHITESPACE);

				if (!(*product = strdup(t))) {
					fprintf(stderr, "Out of memory.\n");
					goto finish;
				}

				break;
			}
		}
	}

	ret = 0;

finish:
	free(line);
	fclose(f);

	if (ret < 0) {
		free(*product);
		free(*vendor);

		*product = *vendor = NULL;
	}

	return ret;
}

static struct udev_device *find_device(struct udev_device *dev, const char *subsys, const char *devtype)
{
	const char *str;

	str = udev_device_get_subsystem(dev);
	if (str == NULL)
		goto try_parent;
	if (strcmp(str, subsys) != 0)
		goto try_parent;

	if (devtype != NULL) {
		str = udev_device_get_devtype(dev);
		if (str == NULL)
			goto try_parent;
		if (strcmp(str, devtype) != 0)
			goto try_parent;
	}
	return dev;
try_parent:
	return udev_device_get_parent_with_subsystem_devtype(dev, SUBSYSTEM, DEVTYPE);
}

int main(int argc, char*argv[]) {

	struct udev *udev = NULL;
	int ret = 1;
	char *sp;
	struct udev_device *dev = NULL, *parent = NULL;
	uint16_t vid = 0, pid = 0;
	char *vendor = NULL, *product = NULL;

	if (argc < 2) {
		fprintf(stderr, "Need to pass sysfs path.\n");
		goto finish;
	}

	if (!(udev = udev_new()))
		goto finish;

	if (asprintf(&sp, "%s%s", udev_get_sys_path(udev), argv[1]) < 0) {
		fprintf(stderr, "Failed to allocate sysfs path.\n");
		goto finish;
	}

	dev = udev_device_new_from_syspath(udev, sp);
	free(sp);

	if (!dev) {
		fprintf(stderr, "Failed to access %s.\n", argv[1]);
		goto finish;
	}

	parent = find_device(dev, SUBSYSTEM, DEVTYPE);
	if (!parent) {
		fprintf(stderr, "Failed to find device.\n");
		goto finish;
	}

	if (get_vid_pid(parent, &vid, &pid) < 0)
		goto finish;

	if (lookup_vid_pid(vid, pid, &vendor, &product) < 0)
		goto finish;

	if (vendor)
		printf("ID_VENDOR_FROM_DATABASE=%s\n", vendor);

	if (product)
		printf("ID_MODEL_FROM_DATABASE=%s\n", product);

	ret = 0;

finish:
	udev_device_unref(dev);
	udev_unref(udev);
	free(vendor);
	free(product);

	return ret;
}
