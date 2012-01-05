/*
 * Create all possible floppy device based on the CMOS type.
 * Based upon code from drivers/block/floppy.c
 *
 * Copyright(C) 2005, SUSE Linux Products GmbH
 *
 * Author: Hannes Reinecke <hare@suse.de>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

#include "libudev.h"
#include "libudev-private.h"

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

static void log_fn(struct udev *udev, int priority,
		   const char *file, int line, const char *fn,
		   const char *format, va_list args)
{
	vsyslog(priority, format, args);
}

int main(int argc, char **argv)
{
	struct udev *udev;
	char *dev;
	char *devname;
	char node[64];
	int type = 0, i, fdnum, c;
	int major = 2, minor;
	uid_t uid = 0;
	gid_t gid = 0;
	mode_t mode = 0660;
	int create_nodes = 0;
	int print_nodes = 0;
	int is_err = 0;

	udev = udev_new();
	if (udev == NULL)
		goto exit;

	udev_log_init("create_floppy_devices");
	udev_set_log_fn(udev, log_fn);
	udev_selinux_init(udev);

	while ((c = getopt(argc, argv, "cudm:U:G:M:t:")) != -1) {
		switch (c) {
		case 'c':
			create_nodes = 1;
			break;
		case 'd':
			print_nodes = 1;
			break;
		case 'U':
			uid = util_lookup_user(udev, optarg);
			break;
		case 'G':
			gid = util_lookup_group(udev, optarg);
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
	devname = strrchr(dev, '/');
	if (devname != NULL)
		devname = &devname[1];
	else
		devname = dev;
	if (strncmp(devname, "fd", 2) != 0) {
		fprintf(stderr,"Device '%s' is not a floppy device\n", dev);
		return 1;
	}

	fdnum = strtol(&devname[2], NULL, 10);
	if (fdnum < 0 || fdnum > 7) {
		fprintf(stderr,"Floppy device number %d out of range (0-7)\n", fdnum);
		return 1;
	}
	if (fdnum > 3)
		fdnum += 124;

	if (major < 1) {
		fprintf(stderr,"Invalid major number %d\n", major);
		return 1;
	}

	if (type < 0 || type >= (int) ARRAY_SIZE(table_sup)) {
		fprintf(stderr,"Invalid CMOS type %d\n", type);
		return 1;
	}

	if (type == 0)
		return 0;

	i = 0;
	while (table_sup[type][i]) {
		sprintf(node, "%s%s", dev, table[table_sup[type][i]]);
		minor = (table_sup[type][i] << 2) + fdnum;
		if (print_nodes)
			printf("%s b %.4o %d %d\n", node, mode, major, minor);
		if (create_nodes) {
			unlink(node);
			udev_selinux_setfscreatecon(udev, node, S_IFBLK | mode);
			mknod(node, S_IFBLK | mode, makedev(major,minor));
			udev_selinux_resetfscreatecon(udev);
			chown(node, uid, gid);
			chmod(node, S_IFBLK | mode);
		}
		i++;
	}

	udev_selinux_exit(udev);
	udev_unref(udev);
	udev_log_close();
exit:
	return 0;
}
