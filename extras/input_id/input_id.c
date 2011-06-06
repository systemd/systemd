/*
 * input_id - input device classification
 *
 * Copyright (C) 2009 Martin Pitt <martin.pitt@ubuntu.com>
 * Portions Copyright (C) 2004 David Zeuthen, <david@fubar.dk>
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
#include <stdlib.h>
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

/* 
 * Read a capability attribute and return bitmask.
 * @param dev udev_device
 * @param attr sysfs attribute name (e. g. "capabilities/key")
 * @param bitmask: Output array which has a sizeof of bitmask_size
 */
static void get_cap_mask (struct udev_device *dev, const char* attr,
			  unsigned long *bitmask, size_t bitmask_size)
{
	struct udev *udev = udev_device_get_udev(dev);
	char text[4096];
	unsigned i;
	char* word;
	unsigned long val;

	snprintf(text, sizeof(text), "%s", udev_device_get_sysattr_value(dev, attr));
	info(udev, "%s raw kernel attribute: %s\n", attr, text);

	memset (bitmask, 0, bitmask_size);
	i = 0;
	while ((word = strrchr(text, ' ')) != NULL) {
		val = strtoul (word+1, NULL, 16);
		if (i < bitmask_size/sizeof(unsigned long))
			bitmask[i] = val;
		else
			info(udev, "ignoring %s block %lX which is larger than maximum size\n", attr, val);
		*word = '\0';
		++i;
	}
	val = strtoul (text, NULL, 16);
	if (i < bitmask_size / sizeof(unsigned long))
		bitmask[i] = val;
	else
		info(udev, "ignoring %s block %lX which is larger than maximum size\n", attr, val);

	if (debug) {
		/* printf pattern with the right unsigned long number of hex chars */
		snprintf(text, sizeof(text), "  bit %%4u: %%0%zilX\n", 2 * sizeof(unsigned long));
		info(udev, "%s decoded bit map:\n", attr);
		val = bitmask_size / sizeof (unsigned long);
		/* skip over leading zeros */
		while (bitmask[val-1] == 0 && val > 0)
			--val;
		for (i = 0; i < val; ++i)
			info(udev, text, i * BITS_PER_LONG, bitmask[i]);
	}
}

/* pointer devices */
static void test_pointers (const unsigned long* bitmask_ev,
			   const unsigned long* bitmask_abs,
			   const unsigned long* bitmask_key,
			   const unsigned long* bitmask_rel)
{
	int is_mouse = 0;
	int is_touchpad = 0;

	if (!test_bit (EV_KEY, bitmask_ev)) {
		if (test_bit (EV_ABS, bitmask_ev) &&
		    test_bit (ABS_X, bitmask_abs) &&
		    test_bit (ABS_Y, bitmask_abs) &&
		    test_bit (ABS_Z, bitmask_abs))
			puts("ID_INPUT_ACCELEROMETER=1");
		return;
	}

	if (test_bit (EV_ABS, bitmask_ev) &&
	    test_bit (ABS_X, bitmask_abs) && test_bit (ABS_Y, bitmask_abs)) {
		if (test_bit (BTN_STYLUS, bitmask_key) || test_bit (BTN_TOOL_PEN, bitmask_key))
			puts("ID_INPUT_TABLET=1");
		else if (test_bit (BTN_TOOL_FINGER, bitmask_key) && !test_bit (BTN_TOOL_PEN, bitmask_key))
			is_touchpad = 1;
		else if (test_bit (BTN_TRIGGER, bitmask_key) || 
			 test_bit (BTN_A, bitmask_key) || 
			 test_bit (BTN_1, bitmask_key))
			puts("ID_INPUT_JOYSTICK=1");
		else if (test_bit (BTN_MOUSE, bitmask_key))
			/* This path is taken by VMware's USB mouse, which has
			 * absolute axes, but no touch/pressure button. */
			is_mouse = 1;
		else if (test_bit (BTN_TOUCH, bitmask_key))
			puts("ID_INPUT_TOUCHSCREEN=1");
	}

	if (test_bit (EV_REL, bitmask_ev) && 
	    test_bit (REL_X, bitmask_rel) && test_bit (REL_Y, bitmask_rel) &&
	    test_bit (BTN_MOUSE, bitmask_key))
		is_mouse = 1;

	if (is_mouse)
		puts("ID_INPUT_MOUSE=1");
	if (is_touchpad)
		puts("ID_INPUT_TOUCHPAD=1");
}

/* key like devices */
static void test_key (struct udev *udev,
		      const unsigned long* bitmask_ev, 
		      const unsigned long* bitmask_key)
{
	unsigned i;
	unsigned long found;
	unsigned long mask;

	/* do we have any KEY_* capability? */
	if (!test_bit (EV_KEY, bitmask_ev)) {
		info(udev, "test_key: no EV_KEY capability\n");
		return;
	}

	/* only consider KEY_* here, not BTN_* */
	found = 0;
	for (i = 0; i < BTN_MISC/BITS_PER_LONG; ++i) {
		found |= bitmask_key[i];
		info(udev, "test_key: checking bit block %lu for any keys; found=%i\n", i*BITS_PER_LONG, found > 0);
	}
	/* If there are no keys in the lower block, check the higher block */
	if (!found) {
		for (i = KEY_OK; i < BTN_TRIGGER_HAPPY; ++i) {
			if (test_bit (i, bitmask_key)) {
				info(udev, "test_key: Found key %x in high block\n", i);
				found = 1;
				break;
			}
		}
	}

	if (found > 0)
		puts("ID_INPUT_KEY=1");

	/* the first 32 bits are ESC, numbers, and Q to D; if we have all of
	 * those, consider it a full keyboard; do not test KEY_RESERVED, though */
	mask = 0xFFFFFFFE;
	if ((bitmask_key[0] & mask) == mask)
		puts("ID_INPUT_KEYBOARD=1");
}

static void help(void)
{
	printf("Usage: input_id [options] <device path>\n"
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
	unsigned long bitmask_ev[NBITS(EV_MAX)];
	unsigned long bitmask_abs[NBITS(ABS_MAX)];
	unsigned long bitmask_key[NBITS(KEY_MAX)];
	unsigned long bitmask_rel[NBITS(REL_MAX)];

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

	/* walk up the parental chain until we find the real input device; the
	 * argument is very likely a subdevice of this, like eventN */
	while (dev != NULL && udev_device_get_sysattr_value(dev, "capabilities/ev") == NULL)
		dev = udev_device_get_parent_with_subsystem_devtype(dev, "input", NULL);

	/* not an "input" class device */
	if (dev == NULL)
		return 0;

	/* Use this as a flag that input devices were detected, so that this
	 * program doesn't need to be called more than once per device */
	puts("ID_INPUT=1");

	get_cap_mask (dev, "capabilities/ev", bitmask_ev, sizeof (bitmask_ev));
	get_cap_mask (dev, "capabilities/abs", bitmask_abs, sizeof (bitmask_abs));
	get_cap_mask (dev, "capabilities/rel", bitmask_rel, sizeof (bitmask_rel));
	get_cap_mask (dev, "capabilities/key", bitmask_key, sizeof (bitmask_key));

	test_pointers(bitmask_ev, bitmask_abs, bitmask_key, bitmask_rel);

	test_key(udev, bitmask_ev, bitmask_key);

	return 0;
}
