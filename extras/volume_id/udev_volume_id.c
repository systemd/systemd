/*
 * udev_volume_id - udev callout to read filesystem label and uuid
 *
 * Copyright (C) 2004 Kay Sievers <kay.sievers@vrfy.org>
 *
 *	sample udev rule for creation of a symlink with the filsystem uuid:
 *	KERNEL="sd*", PROGRAM="/sbin/udev_volume_id -u", SYMLINK="%c"
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
 * 
 *	This program is distributed in the hope that it will be useful, but
 *	WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *	General Public License for more details.
 * 
 *	You should have received a copy of the GNU General Public License along
 *	with this program; if not, write to the Free Software Foundation, Inc.,
 *	675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

#include "../../libsysfs/sysfs/libsysfs.h"
#include "../../udev_lib.h"
#include "../../logging.h"
#include "volume_id.h"
#include "dasdlabel.h"

#ifdef LOG
unsigned char logname[LOGNAME_SIZE];
void log_message(int level, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vsyslog(level, format, args);
	va_end(args);
}
#endif

static struct volume_id *open_classdev(struct sysfs_class_device *class_dev)
{
	struct volume_id *vid;
	struct sysfs_attribute *attr;
	int major, minor;

	attr = sysfs_get_classdev_attr(class_dev, "dev");

	if (attr == NULL) {
		printf("error reading 'dev' attribute\n");
		return NULL;
	}

	if (sscanf(attr->value, "%u:%u", &major, &minor) != 2) {
		printf("error getting major/minor number\n");
		return NULL;
	}

	vid = volume_id_open_dev_t(makedev(major, minor));
	if (vid == NULL) {
		printf("error open volume\n");
		return NULL;
	}

	return vid;
}

int main(int argc, char *argv[])
{
	const char help[] = "usage: udev_volume_id [-t|-l|-u|-d]\n"
			    "       -t filesystem type\n"
			    "       -l filesystem label\n"
			    "       -u filesystem uuid\n"
			    "       -d disk label from main device\n"
			    "\n";
	static const char short_options[] = "htlud";
	int option;
	char sysfs_path[SYSFS_PATH_MAX];
	char dev_path[SYSFS_PATH_MAX];
	struct sysfs_class_device *class_dev = NULL;
	struct sysfs_class_device *class_dev_parent = NULL;
	struct volume_id *vid = NULL;
	char *devpath;
	char probe = 'p';
	char print = 'a';
	char dasd_label[7];
	static char name[VOLUME_ID_LABEL_SIZE];
	int len, i, j;
	int rc = 1;

	while (1) {
		option = getopt(argc, argv, short_options);
		if (option == -1)
			break;

		switch (option) {
		case 't':
			print = 't';
			continue;
		case 'l':
			print = 'l';
			continue;
		case 'u':
			print = 'u';
			continue;
		case 'd':
			probe = 'd';
			continue;
		case 'h':
		case '?':
		default:
			printf(help);
			exit(1);
		}
	}

	devpath = getenv("DEVPATH");
	if (devpath == NULL) {
		printf("error DEVPATH empty\n");
		goto exit;
	}

	if (sysfs_get_mnt_path(sysfs_path, SYSFS_PATH_MAX) != 0) {
		printf("error getting sysfs mount path\n");
		goto exit;
	}

	strfieldcpy(dev_path, sysfs_path);
	strfieldcat(dev_path, devpath);

	class_dev = sysfs_open_class_device_path(dev_path);
	if (class_dev == NULL) {
		printf("error getting class device\n");
		goto exit;
	}

	switch(probe) {
	case 'p' :
		/* open block device */
		vid = open_classdev(class_dev);
		if (vid == NULL)
			goto exit;
		if (volume_id_probe(vid, ALL) == 0)
			goto print;
		break;
	case 'd' :
		/* if we are on a partition, close it and open main block device */
		class_dev_parent = sysfs_get_classdev_parent(class_dev);
		if (class_dev_parent != NULL) {
			volume_id_close(vid);
			vid = open_classdev(class_dev_parent);
		} else {
			vid = open_classdev(class_dev_parent);
		}
		if (vid == NULL)
			goto exit;
		if (probe_ibm_partition(vid->fd, dasd_label) == 0) {
			vid->fs_name = "dasd";
			strncpy(vid->label_string, dasd_label, 6);
			vid->label_string[6] = '\0';
			goto print;
		}
		break;
	}

	printf("unknown volume type\n");
	goto exit;


print:
	len = strnlen(vid->label_string, VOLUME_ID_LABEL_SIZE);

	/* remove trailing spaces */
	while (len > 0 && isspace(vid->label_string[len-1]))
		len--;
	name[len] = '\0';

	/* substitute chars */
	i = 0;
	j = 0;
	while (j < len) {
		switch(vid->label_string[j]) {
		case '/' :
			break;
		case ' ' :
			name[i++] = '_';
			break;
		default :
			name[i++] = vid->label_string[j];
		}
		j++;
	}
	name[i] = '\0';

	switch (print) {
	case 't':
		printf("%s\n", vid->fs_name);
		break;
	case 'l':
		if (name[0] == '\0') {
			rc = 2;
			goto exit;
		}
		printf("%s\n", name);
		break;
	case 'u':
		if (vid->uuid_string[0] == '\0') {
			rc = 2;
			goto exit;
		}
		printf("%s\n", vid->uuid_string);
		break;
	case 'a':
		printf("T:%s\n", vid->fs_name);
		printf("L:%s\n", vid->label_string);
		printf("N:%s\n", name);
		printf("U:%s\n", vid->uuid_string);
	}
	rc = 0;

exit:
	if (class_dev != NULL)
		sysfs_close_class_device(class_dev);
	if (vid != NULL)
		volume_id_close(vid);

	exit(rc);
}
