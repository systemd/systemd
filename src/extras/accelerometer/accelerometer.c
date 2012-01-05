/*
 * accelerometer - exports device orientation through property
 *
 * When an "change" event is received on an accelerometer,
 * open its device node, and from the value, as well as the previous
 * value of the property, calculate the device's new orientation,
 * and export it as ID_INPUT_ACCELEROMETER_ORIENTATION.
 *
 * Possible values are:
 * undefined
 * * normal
 * * bottom-up
 * * left-up
 * * right-up
 *
 * The property will be persistent across sessions, and the new
 * orientations can be deducted from the previous one (it allows
 * for a threshold for switching between opposite ends of the
 * orientation).
 *
 * Copyright (C) 2011 Red Hat, Inc.
 * Author:
 *   Bastien Nocera <hadess@hadess.net>
 *
 * orientation_calc() from the sensorfw package
 * Copyright (C) 2009-2010 Nokia Corporation
 * Authors:
 *   Üstün Ergenoglu <ext-ustun.ergenoglu@nokia.com>
 *   Timo Rongas <ext-timo.2.rongas@nokia.com>
 *   Lihan Guo <lihan.guo@digia.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with keymap; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
 */

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <limits.h>
#include <linux/limits.h>
#include <linux/input.h>

#include "libudev.h"
#include "libudev-private.h"

/* we must use this kernel-compatible implementation */
#define BITS_PER_LONG (sizeof(unsigned long) * 8)
#define NBITS(x) ((((x)-1)/BITS_PER_LONG)+1)
#define OFF(x)  ((x)%BITS_PER_LONG)
#define BIT(x)  (1UL<<OFF(x))
#define LONG(x) ((x)/BITS_PER_LONG)
#define test_bit(bit, array)    ((array[LONG(bit)] >> OFF(bit)) & 1)

static int debug = 0;

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

typedef enum {
	ORIENTATION_UNDEFINED,
	ORIENTATION_NORMAL,
	ORIENTATION_BOTTOM_UP,
	ORIENTATION_LEFT_UP,
	ORIENTATION_RIGHT_UP
} OrientationUp;

static const char *orientations[] = {
	"undefined",
	"normal",
	"bottom-up",
	"left-up",
	"right-up",
	NULL
};

#define ORIENTATION_UP_UP ORIENTATION_NORMAL

#define DEFAULT_THRESHOLD 250
#define RADIANS_TO_DEGREES 180.0/M_PI
#define SAME_AXIS_LIMIT 5

#define THRESHOLD_LANDSCAPE  25
#define THRESHOLD_PORTRAIT  20

static const char *
orientation_to_string (OrientationUp o)
{
	return orientations[o];
}

static OrientationUp
string_to_orientation (const char *orientation)
{
	int i;

	if (orientation == NULL)
		return ORIENTATION_UNDEFINED;
	for (i = 0; orientations[i] != NULL; i++) {
		if (strcmp (orientation, orientations[i]) == 0)
			return i;
	}
	return ORIENTATION_UNDEFINED;
}

static OrientationUp
orientation_calc (OrientationUp prev,
		  int x, int y, int z)
{
	int rotation;
	OrientationUp ret = prev;

	/* Portrait check */
	rotation = round(atan((double) x / sqrt(y * y + z * z)) * RADIANS_TO_DEGREES);

	if (abs(rotation) > THRESHOLD_PORTRAIT) {
		ret = (rotation < 0) ? ORIENTATION_LEFT_UP : ORIENTATION_RIGHT_UP;

		/* Some threshold to switching between portrait modes */
		if (prev == ORIENTATION_LEFT_UP || prev == ORIENTATION_RIGHT_UP) {
			if (abs(rotation) < SAME_AXIS_LIMIT) {
				ret = prev;
			}
		}

	} else {
		/* Landscape check */
		rotation = round(atan((double) y / sqrt(x * x + z * z)) * RADIANS_TO_DEGREES);

		if (abs(rotation) > THRESHOLD_LANDSCAPE) {
			ret = (rotation < 0) ? ORIENTATION_BOTTOM_UP : ORIENTATION_NORMAL;

			/* Some threshold to switching between landscape modes */
			if (prev == ORIENTATION_BOTTOM_UP || prev == ORIENTATION_NORMAL) {
				if (abs(rotation) < SAME_AXIS_LIMIT) {
					ret = prev;
				}
			}
		}
	}

	return ret;
}

static OrientationUp
get_prev_orientation(struct udev_device *dev)
{
	const char *value;

	value = udev_device_get_property_value(dev, "ID_INPUT_ACCELEROMETER_ORIENTATION");
	if (value == NULL)
		return ORIENTATION_UNDEFINED;
	return string_to_orientation(value);
}

#define SET_AXIS(axis, code_) if (ev[i].code == code_) { if (got_##axis == 0) { axis = ev[i].value; got_##axis = 1; } }

/* accelerometers */
static void test_orientation(struct udev *udev,
			     struct udev_device *dev,
			     const char *devpath)
{
	OrientationUp old, new;
	int fd, r;
	struct input_event ev[64];
	int got_syn = 0;
	int got_x, got_y, got_z;
	int x = 0, y = 0, z = 0;
	char text[64];

	old = get_prev_orientation(dev);

	if ((fd = open(devpath, O_RDONLY)) < 0)
		return;

	got_x = got_y = got_z = 0;

	while (1) {
		int i;

		r = read(fd, ev, sizeof(struct input_event) * 64);

		if (r < (int) sizeof(struct input_event))
			return;

		for (i = 0; i < r / (int) sizeof(struct input_event); i++) {
			if (got_syn == 1) {
				if (ev[i].type == EV_ABS) {
					SET_AXIS(x, ABS_X);
					SET_AXIS(y, ABS_Y);
					SET_AXIS(z, ABS_Z);
				}
			}
			if (ev[i].type == EV_SYN && ev[i].code == SYN_REPORT) {
				got_syn = 1;
			}
			if (got_x && got_y && got_z)
				goto read_dev;
		}
	}

read_dev:
	close(fd);

	if (!got_x || !got_y || !got_z)
		return;

	new = orientation_calc(old, x, y, z);
	snprintf(text, sizeof(text), "ID_INPUT_ACCELEROMETER_ORIENTATION=%s", orientation_to_string(new));
	puts(text);
}

static void help(void)
{
	printf("Usage: accelerometer [options] <device path>\n"
	       "  --debug         debug to stderr\n"
	       "  --help          print this help text\n\n");
}

int main (int argc, char** argv)
{
	struct udev *udev;
	struct udev_device *dev;

	static const struct option options[] = {
		{ "debug", no_argument, NULL, 'd' },
		{ "help", no_argument, NULL, 'h' },
		{}
	};

	char devpath[PATH_MAX];
	char *devnode;
	const char *id_path;
	struct udev_enumerate *enumerate;
	struct udev_list_entry *list_entry;

	udev = udev_new();
	if (udev == NULL)
		return 1;

	udev_log_init("input_id");
	udev_set_log_fn(udev, log_fn);

	/* CLI argument parsing */
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
			help();
			exit(0);
		default:
			exit(1);
		}
	}

	if (argv[optind] == NULL) {
		help();
		exit(1);
	}

	/* get the device */
	snprintf(devpath, sizeof(devpath), "%s/%s", udev_get_sys_path(udev), argv[optind]);
	dev = udev_device_new_from_syspath(udev, devpath);
	if (dev == NULL) {
		fprintf(stderr, "unable to access '%s'\n", devpath);
		return 1;
	}

	id_path = udev_device_get_property_value(dev, "ID_PATH");
	if (id_path == NULL) {
		fprintf (stderr, "unable to get property ID_PATH for '%s'", devpath);
		return 0;
	}

	/* Get the children devices and find the devnode
	 * FIXME: use udev_enumerate_add_match_children() instead
	 * when it's available */
	devnode = NULL;
	enumerate = udev_enumerate_new(udev);
	udev_enumerate_add_match_property(enumerate, "ID_PATH", id_path);
	udev_enumerate_add_match_subsystem(enumerate, "input");
	udev_enumerate_scan_devices(enumerate);
	udev_list_entry_foreach(list_entry, udev_enumerate_get_list_entry(enumerate)) {
		struct udev_device *device;
		const char *node;

		device = udev_device_new_from_syspath(udev_enumerate_get_udev(enumerate),
						      udev_list_entry_get_name(list_entry));
		if (device == NULL)
			continue;
		/* Already found it */
		if (devnode != NULL) {
			udev_device_unref(device);
			continue;
		}

		node = udev_device_get_devnode(device);
		if (node == NULL) {
			udev_device_unref(device);
			continue;
		}
		/* Use the event sub-device */
		if (strstr(node, "/event") == NULL) {
			udev_device_unref(device);
			continue;
		}

		devnode = strdup(node);
		udev_device_unref(device);
	}

	if (devnode == NULL) {
		fprintf(stderr, "unable to get device node for '%s'\n", devpath);
		return 0;
	}

	info(udev, "Opening accelerometer device %s\n", devnode);
	test_orientation(udev, dev, devnode);
	free(devnode);

	return 0;
}
