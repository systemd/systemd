/*
 * vol_id - udev callout to read filesystem label and uuid
 *
 * Copyright (C) 2005 Kay Sievers <kay.sievers@vrfy.org>
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <grp.h>
#include <sys/ioctl.h>

#include "../../udev.h"
#include "libvolume_id/libvolume_id.h"

#define BLKGETSIZE64 _IOR(0x12,114,size_t)

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

static void set_str(char *to, const char *from, size_t count)
{
	size_t i, j, len;

	/* strip trailing whitespace */
	len = strnlen(from, count);
	while (len && isspace(from[len-1]))
		len--;

	/* strip leading whitespace */
	i = 0;
	while (isspace(from[i]) && (i < len))
		i++;

	j = 0;
	while (i < len) {
		/* substitute multiple whitespace */
		if (isspace(from[i])) {
			while (isspace(from[i]))
				i++;
			to[j++] = '_';
		}
		/* skip chars */
		if (from[i] == '/') {
			i++;
			continue;
		}
		to[j++] = from[i++];
	}
	to[j] = '\0';
}

int main(int argc, char *argv[])
{
	const char help[] = "usage: vol_id [--export|-t|-l|-u] <device>\n"
			    "       --export\n"
			    "       -t filesystem type\n"
			    "       -l filesystem label\n"
			    "       -u filesystem uuid\n"
			    "\n";
	enum print_type {
		PRINT_EXPORT,
		PRINT_TYPE,
		PRINT_LABEL,
		PRINT_UUID,
	} print = PRINT_EXPORT;
	struct volume_id *vid = NULL;
	static char name[VOLUME_ID_LABEL_SIZE];
	int i;
	uint64_t size;
	const char *node = NULL;
	uid_t nobody_uid;
	gid_t nobody_gid;
	int rc = 0;

	logging_init("vol_id");

	for (i = 1 ; i < argc; i++) {
		char *arg = argv[i];

		if (strcmp(arg, "--export") == 0) {
			print = PRINT_EXPORT;
		} else if (strcmp(arg, "-t") == 0) {
			print = PRINT_TYPE;
		} else if (strcmp(arg, "-l") == 0) {
			print = PRINT_LABEL;
		} else if (strcmp(arg, "-u") == 0) {
			print = PRINT_UUID;
		} else
			node = arg;
	}
	if (!node) {
		err("no node specified");
		fprintf(stderr, help);
		rc = 1;
		goto exit;
	}

	vid = volume_id_open_node(node);
	if (vid == NULL) {
		fprintf(stderr, "%s: error open volume\n", node);
		rc = 2;
		goto exit;
	}

	if (ioctl(vid->fd, BLKGETSIZE64, &size) != 0)
		size = 0;
	dbg("BLKGETSIZE64=%llu", size);

	/* drop all privileges */
	nobody_uid = lookup_user("nobody");
	nobody_gid = lookup_group("nogroup");
	if (nobody_uid > 0 && nobody_gid > 0) {
		if (setgroups(0, NULL) != 0 ||
		    setgid(nobody_gid) != 0 ||
		    setuid(nobody_uid) != 0) {
			rc = 3;
			goto exit;
		}
	}

	if (volume_id_probe_all(vid, 0, size) == 0)
		goto print;

	if (print != PRINT_EXPORT)
		fprintf(stderr, "%s: unknown volume type\n", node);
	rc = 4;
	goto exit;

print:
	set_str(name, vid->label, sizeof(vid->label));
	replace_untrusted_chars(name);

	switch (print) {
	case PRINT_EXPORT:
		printf("ID_FS_USAGE=%s\n", vid->usage);
		printf("ID_FS_TYPE=%s\n", vid->type);
		printf("ID_FS_VERSION=%s\n", vid->type_version);
		printf("ID_FS_UUID=%s\n", vid->uuid);
		printf("ID_FS_LABEL=%s\n", vid->label);
		printf("ID_FS_LABEL_SAFE=%s\n", name);
		break;
	case PRINT_TYPE:
		printf("%s\n", vid->type);
		break;
	case PRINT_LABEL:
		if (name[0] == '\0' ||
		    (vid->usage_id != VOLUME_ID_FILESYSTEM && vid->usage_id != VOLUME_ID_DISKLABEL)) {
			rc = 3;
			goto exit;
		}
		printf("%s\n", name);
		break;
	case PRINT_UUID:
		if (vid->uuid[0] == '\0' || vid->usage_id != VOLUME_ID_FILESYSTEM) {
			rc = 4;
			goto exit;
		}
		printf("%s\n", vid->uuid);
		break;
	}

exit:
	if (vid != NULL)
		volume_id_close(vid);

	logging_close();
	return rc;
}
