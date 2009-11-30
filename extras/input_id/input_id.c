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
#include <limits.h>
#include <linux/input.h>

/* we must use this kernel-compatible implementation */
#define BITS_PER_LONG (sizeof(unsigned long) * 8)
#define NBITS(x) ((((x)-1)/BITS_PER_LONG)+1)
#define OFF(x)  ((x)%BITS_PER_LONG)
#define BIT(x)  (1UL<<OFF(x))
#define LONG(x) ((x)/BITS_PER_LONG)
#define test_bit(bit, array)    ((array[LONG(bit)] >> OFF(bit)) & 1)

/* 
 * Read a capabilities/name file and return bitmask.
 * @param path File to open
 * @param bitmask: Output array; must have max_size elements
 */
static void get_cap_mask (const char *path, unsigned long *bitmask, size_t max_size)
{
	FILE* f;
        int i;
	char text[4096];
	char* word;
	unsigned long val;

	f = fopen(path, "r");
	if (f == NULL) {
		perror("opening caps file");
		exit(1);
	}
	if (fgets(text, sizeof(text), f) == NULL) {
		perror("fgets");
		exit(1);
	}
	fclose(f);
	
        memset (bitmask, 0, max_size);
	i = 0;
        while ((word = strrchr(text, ' ')) != NULL) {
                val = strtoul (word+1, NULL, 16);
                bitmask[i] = val;
		*word = '\0';
		++i;
        }
	val = strtoul (text, NULL, 16);
	bitmask[i] = val;
}

/* pointer devices */
static void test_pointers (const unsigned long* bitmask_abs, const unsigned long* bitmask_key, const unsigned long* bitmask_rel)
{
	int is_mouse = 0;
	int is_touchpad = 0;

	if (test_bit (ABS_X, bitmask_abs) && test_bit (ABS_Y, bitmask_abs)) {
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
	}

	if (test_bit (REL_X, bitmask_rel) && test_bit (REL_Y, bitmask_rel))
		is_mouse = 1;

	if (is_mouse)
		puts("ID_INPUT_MOUSE=1");
	if (is_touchpad)
		puts("ID_INPUT_TOUCHPAD=1");
}

/* key like devices */
static void test_key (const unsigned long* bitmask_key)
{
	unsigned i;
	unsigned long acc;
	unsigned long mask;

	/* do we have any KEY_* capability? */
	acc = 0;
	for (i = 0; i < BTN_MISC/BITS_PER_LONG; ++i)
	    acc |= bitmask_key[i];
	if (acc > 0)
		puts("ID_INPUT_KEY=1");

	/* the first 32 bits are ESC, numbers, and Q to D; if we have all of
	 * those, consider it a full keyboard; do not test KEY_RESERVED, though */
	mask = 0xFFFFFFFE;
	if ((bitmask_key[0] & mask) == mask)
		puts("ID_INPUT_KEYBOARD=1");
}

int main (int argc, char** argv)
{
	char capfile[PATH_MAX];
	unsigned long bitmask_abs[NBITS(ABS_MAX)];
	unsigned long bitmask_key[NBITS(KEY_MAX)];
        unsigned long bitmask_rel[NBITS(REL_MAX)];

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <device path (without /sys)>\n", argv[0]);
		exit(1);
	}

	/* Use this as a flag that input devices were detected, so that this
	 * program doesn't need to be called more than once per device */
	puts("ID_INPUT=1");

	snprintf(capfile, sizeof(capfile), "/sys/%s/device/capabilities/abs", argv[1]);
	get_cap_mask (capfile, bitmask_abs, sizeof (bitmask_abs));
	snprintf(capfile, sizeof(capfile), "/sys/%s/device/capabilities/rel", argv[1]);
	get_cap_mask (capfile, bitmask_rel, sizeof (bitmask_rel));
	snprintf(capfile, sizeof(capfile), "/sys/%s/device/capabilities/key", argv[1]);
	get_cap_mask (capfile, bitmask_key, sizeof (bitmask_key));

	test_pointers(bitmask_abs, bitmask_key, bitmask_rel);

	test_key(bitmask_key);

	return 0;
}
