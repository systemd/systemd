/*
 * create_floppy_devices
 *
 * Create all possible floppy device based on the CMOS type.
 * Based upon code from drivers/block/floppy.c
 *
 * Copyright(C) 2005, SUSE Linux Products GmbH
 *
 * Author:
 *	Hannes Reinecke <hare@suse.de>
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>

#include "../../udev.h"
#include "../../udev_selinux.h"

static char *table[] = {
	"", "d360", "h1200", "u360", "u720", "h360", "h720",
	"u1440", "u2880", "CompaQ", "h1440", "u1680", "h410",
	"u820", "h1476", "u1722", "h420", "u830", "h1494", "u1743",
	"h880", "u1040", "u1120", "h1600", "u1760", "u1920",
	"u3200", "u3520", "u3840", "u1840", "u800", "u1600",
	NULL
};

static int t360[] = { 1, 0 };
static int t1200[] = { 2, 5, 6, 10, 12, 14, 16, 18, 20, 23, 0 };
static int t3in[] = { 8, 9, 26, 27, 28, 7, 11, 15, 19, 24, 25, 29, 31, 3, 4, 13, 17, 21, 22, 30, 0 };
static int *table_sup[] = { NULL, t360, t1200, t3in+5+8, t3in+5, t3in, t3in };

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

int main(int argc, char **argv)
{
	char *dev;
	char node[64];
	int type = 0, i, fdnum, c;
	int major = 2, minor;
	uid_t uid = 0;
	gid_t gid = 0;
	mode_t mode = 0;
	int create_nodes = 0;
	int print_nodes = 0;
	int unlink_nodes = 0;
	int is_err = 0;

	while ((c = getopt(argc, argv, "cudm:U:G:M:t:")) != -1) {
		switch (c) {
		case 'c':
			create_nodes = 1;
			unlink_nodes = 0;
			break;
		case 'u':
			unlink_nodes = 1;
			create_nodes = 0;
			break;
		case 'd':
			print_nodes = 1;
			break;
		case 'U':
			uid = lookup_user(optarg);
			break;
		case 'G':
			gid = lookup_group(optarg);
			break;
		case 'M':
			mode = strtol(optarg, NULL, 0);
			mode = mode & 0666;
			break;
		case 'm':
			major = strtol(optarg, NULL, 0);
			break;
		case 't':
			type = strtol(optarg, NULL, 0);
			break;
		default:
			is_err++;
			break;
		}
	}

	if (is_err || optind >= argc) {
		printf("Usage:  %s [OPTION] device\n"
		       "  -c   create\n"
		       "  -d   debug\n"
		       "  -m   Major number\n"
		       "  -t   floppy type number\n"
		       "  -U   device node user ownership\n"
		       "  -G   device node group owner\n"
		       "  -M   device node mode\n"
		       "\n", argv[0]);
		return 1;
	}

	dev = argv[optind];
	if (dev[strlen(dev) - 3] != 'f' || dev[strlen(dev) -2 ] != 'd') {
		fprintf(stderr,"Device '%s' is not a floppy device\n", dev);
		return 1;
	}

	fdnum = strtol(dev + 2, NULL, 10);
	if (fdnum < 0 || fdnum > 7) {
		fprintf(stderr,"Floppy device number %d out of range (0-7)\n", fdnum);
		return 1;
	}
	if (fdnum > 3)
		fdnum += 128;

	if (major < 1) {
		fprintf(stderr,"Invalid major number %d\n", major);
		return 1;
	}

	if (type < 0 || type > (int) sizeof(table)) {
		fprintf(stderr,"Invalid CMOS type %d\n", type);
		return 1;
	}

	if (type == 0)
		return 0;

	selinux_init();

	i = 0;
	while (table_sup[type][i]) {
		sprintf(node, "%s%s", dev, table[table_sup[type][i]]);
		minor = (table_sup[type][i] << 2) + fdnum;
		if (print_nodes)
			printf("%s b %d %d %d\n", node, mode, major, minor);
		if (create_nodes) {
			unlink(node);
			selinux_setfscreatecon(node, NULL, mode);
			mknod(node, S_IFBLK | mode, makedev(major,minor));
			selinux_resetfscreatecon();
			chown(node, uid, gid);
		}
		i++;
	}

	selinux_exit();
	return 0;
}
