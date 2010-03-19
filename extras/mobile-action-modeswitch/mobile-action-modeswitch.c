/*
 * Mobile action cable mode switcher
 *
 * Copyright (C) 2008 - 2010  Dan Williams <dcbw@redhat.com>
 * Copyright (C) 2008  Peter Henn <support@option.com>
 *
 * Heavily based on the 'ozerocdoff' tool by Peter Henn.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details:
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdarg.h>
#include <getopt.h>

#include <usb.h>

#include "utils.h"

#include "ma8280p_us.h"

struct usb_dev_handle *handle = NULL;

typedef struct usb_device * (*FindFunc) (int vid, int pid);
typedef int (*SwitchFunc) (struct usb_dev_handle *dh, struct usb_device *dev);

typedef enum {
	ST_UNKNOWN = 0,
	ST_MA8280P
} SwitchType;

typedef struct SwitchEntry {
	SwitchType st;
	const char *clopt;
	FindFunc find_func;
	SwitchFunc switch_func;
} SwitchEntry;

static SwitchEntry switch_types[] = {
	{ ST_MA8280P, "mobile-action-8280p", NULL, ma8280p_switch },
	{ ST_UNKNOWN, NULL, NULL }
};

static struct usb_device *
generic_find (int vid, int pid)
{
	struct usb_bus *bus;
	struct usb_device *dev;

	for (bus = usb_get_busses(); bus; bus = bus->next) {
		for (dev = bus->devices; dev; dev = dev->next) {
			if (dev->descriptor.idVendor == vid && dev->descriptor.idProduct == pid) {
				debug ("Found device '%s'", dev->filename);
				return dev;
			}
		}
	}
	return NULL;
}

static void
release_usb_device (int param)
{
	usb_release_interface (handle, 0);
	usb_close (handle);
}

static void
print_usage (void)
{
	printf ("Usage: mobile-action-modeswitch [-hdq] [-l <file>] -v <vendor-id> -p <product-id> -t <type>\n"
	        " -h, --help               show this help message\n"
	        " -v, --vendor <n>         target USB vendor ID\n"
	        " -p, --product <n>        target USB product ID\n"
	        " -t, --type <type>        type of switch to attempt, varies by device:\n"
	        "                               mobile-action-8280p   - For Mobile Action 8xxxP USB cables\n"
	        " -l, --log <file>         log output to a file\n"
	        " -q, --quiet              don't print anything to stdout\n"
	        " -d, --debug              display debugging messages\n\n"
	        "Examples:\n"
	        "   mobile-action-modeswitch -v 0x0df7 -p 0x8000 -t mobile-action-8280p\n");
}

static SwitchEntry *
parse_type (const char *s)
{
	SwitchEntry *entry = &switch_types[0];

	while (entry->clopt) {
		if (!strcmp (entry->clopt, s))
			return entry;
		entry++;
	}

	return NULL;
}

static void
do_exit (int val)
{
	log_shutdown ();
	exit (val);
}

int main(int argc, char **argv)
{
	static struct option options[] = {
		{ "help",	 no_argument,       NULL, 'h' },
		{ "vendor",  required_argument, NULL, 'v' },
		{ "product", required_argument, NULL, 'p' },
		{ "type",    required_argument, NULL, 't' },
		{ "log",     required_argument, NULL, 'l' },
		{ "debug",   no_argument,       NULL, 'd' },
		{ "quiet",   no_argument,       NULL, 'q' },
		{ NULL, 0, NULL, 0}
	};

	struct usb_device *dev;
	int vid = 0, pid = 0;
	const char *logpath = NULL;
	char buffer[256];
	int ret, quiet = 0, debug = 0;
	SwitchEntry *sentry = NULL;

	while (1) {
		int option;

		option = getopt_long(argc, argv, "hv:p:l:t:dq", options, NULL);
		if (option == -1)
			break;

		switch (option) {
		case 'v':
			vid = strtol (optarg, NULL, 0);
			break;
		case 'p':
			pid = strtol (optarg, NULL, 0);
			break;
		case 't':
			sentry = parse_type (optarg);
			if (!sentry) {
				error ("unknown switch type '%s'", optarg);
				print_usage ();
				exit (1);
			}
			break;
		case 'l':
			logpath = optarg;
			break;
		case 'q':
			quiet = 1;
			break;
		case 'd':
			debug = 1;
			break;
		case 'h':
		default:
			print_usage ();
			exit (1);
		}
	}

	if (log_startup (logpath, debug, quiet)) {
		fprintf (stderr, "Couldn't open/create logfile %s", logpath);
		exit (2);
	}

	if (!sentry) {
		if (!quiet)
			print_usage ();
		else
			error ("missing device switch type.");
		do_exit (3);
	}

	if (!vid || !pid) {
		if (!quiet)
			print_usage ();
		else
			error ("missing vendor and device IDs.");
		do_exit (3);
	}

	usb_init();

	if (usb_find_busses() < 0) {
		error ("no USB busses found.");
		do_exit (4);
	}

	if (usb_find_devices() < 0) {
		error ("no USB devices found.");
		do_exit (4);
	}

	if (sentry->find_func)
		dev = (*sentry->find_func) (vid, pid);
	else
		dev = generic_find (vid, pid);
	if (dev == NULL) {
		error ("no device found.");
		do_exit (5);
	}

	handle = usb_open (dev);
	if (handle == NULL) {
		error ("%s: could not access the device.",
		         dev->filename);
		do_exit (6);
	}

	/* detach running default driver */
	signal (SIGTERM, release_usb_device);
	ret = usb_get_driver_np (handle, 0, buffer, sizeof (buffer));
	if (ret == 0) {
		debug ("%s: found already attached driver '%s'", dev->filename, buffer);

		ret = usb_detach_kernel_driver_np (handle, 0);
		if (ret != 0) {
			debug ("%s: error: unable to detach current driver.", dev->filename);
			usb_close (handle);
			do_exit (7);
		}
	}

	ret = usb_claim_interface (handle, 0);
	if (ret != 0) {
		debug ("%s: couldn't claim device's USB interface: %d.",
		       dev->filename, ret);
		usb_close (handle);
		do_exit (8);
	}

	ret = (*sentry->switch_func) (handle, dev);
	if (ret < 0) {
		debug ("%s: failed to switch device to serial mode.", dev->filename);
		usb_release_interface (handle, 0);
		usb_close (handle);
		do_exit(9);
	}

	usb_release_interface (handle, 0);

	ret = usb_close (handle);
	if (ret < 0)
		debug ("%s: failed to close the device.", dev->filename);

	do_exit (0);
	return 0;
}
