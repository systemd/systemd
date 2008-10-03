/*
 * vol_id - read filesystem label and uuid
 *
 * Copyright (C) 2005-2008 Kay Sievers <kay.sievers@vrfy.org>
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <getopt.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/ioctl.h>

#include "../../udev/udev.h"
#include "lib/libvolume_id.h"

#define BLKGETSIZE64 _IOR(0x12,114,size_t)

static int debug;
struct udev *udev_ctx;

static void log_fn(struct udev *udev, int priority,
		   const char *file, int line, const char *fn,
		   const char *format, va_list args)
{
	if (debug) {
		fprintf(stderr, "%s: ", fn != NULL ? fn : file);
		vfprintf(stderr, format, args);
	} else {
		vsyslog(priority, format, args);
	}
}

static void vid_log(int priority, const char *file, int line, const char *format, ...)
{
	va_list args;

	if (priority > udev_get_log_priority(udev_ctx))
		return;
	va_start(args, format);
	log_fn(udev_ctx, priority, file, line, NULL, format, args);
	va_end(args);
	return;
}

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

static int all_probers(volume_id_probe_fn_t probe_fn,
		       struct volume_id *id, uint64_t off, uint64_t size,
		       void *data)
{
	const char *type;

	if (probe_fn(id, off, size) == 0)
		if (volume_id_get_type(id, &type))
			printf("%s\n", type);

	return 0;
}

int main(int argc, char *argv[])
{
	static const struct option options[] = {
		{ "label", no_argument, NULL, 'l' },
		{ "label-raw", no_argument, NULL, 'L' },
		{ "uuid", no_argument, NULL, 'u' },
		{ "type", no_argument, NULL, 't' },
		{ "export", no_argument, NULL, 'x' },
		{ "skip-raid", no_argument, NULL, 's' },
		{ "size", required_argument, NULL, 'S' },
		{ "probe-all", no_argument, NULL, 'a' },
		{ "offset", optional_argument, NULL, 'o' },
		{ "debug", no_argument, NULL, 'd' },
		{ "help", no_argument, NULL, 'h' },
		{}
	};

	enum print_type {
		PRINT_EXPORT,
		PRINT_TYPE,
		PRINT_LABEL,
		PRINT_UUID,
		PRINT_LABEL_RAW,
	} print = PRINT_EXPORT;

	struct volume_id *vid = NULL;
	char label_safe[256];
	char label_enc[256];
	char uuid_safe[256];
	char uuid_enc[256];
	char type_enc[256];
	char type_version_enc[256];
	uint64_t size = 0;
	int skip_raid = 0;
	int probe_all = 0;
	uint64_t offset = 0;
	const char *node;
	int fd;
	const char *label, *uuid, *type, *type_version, *usage;
	int retval;
	int rc = 0;

	udev_ctx = udev_new();
	if (udev_ctx == NULL)
		goto exit;
	logging_init("vol_id");
	udev_set_log_fn(udev_ctx, log_fn);

	/* hook in our debug into libvolume_id */
	volume_id_log_fn = vid_log;

	while (1) {
		int option;

		option = getopt_long(argc, argv, "lLutxsS:aodh", options, NULL);
		if (option == -1)
			break;

		switch (option) {
		case 'd':
			debug = 1;
			if (udev_get_log_priority(udev_ctx) < LOG_INFO)
				udev_set_log_priority(udev_ctx, LOG_INFO);
			break;
		case 'l':
			print = PRINT_LABEL;
			break;
		case 'L':
			print = PRINT_LABEL_RAW;
			break;
		case 'u':
			print = PRINT_UUID;
			break;
		case 't':
			print = PRINT_TYPE;
			break;
		case 'x':
			print = PRINT_EXPORT;
			break;
		case 's':
			skip_raid = 1;
			break;
		case 'a':
			probe_all = 1;
			break;
		case 'S':
			if (optarg[0] != '\0')
				size = strtoull(optarg, NULL, 0);
			break;
		case 'o':
			if (optarg[0] != '\0')
				offset = strtoull(optarg, NULL, 0);
			break;
		case 'h':
			printf("Usage: vol_id [options] <device>\n"
			    " --export         export key/value pairs\n"
			    " --type           filesystem type\n"
			    " --label          filesystem label\n"
			    " --label-raw      raw label\n"
			    " --uuid           filesystem uuid\n"
			    " --skip-raid      don't probe for raid\n"
			    " --probe-all      find possibly conflicting signatures\n"
			    " --offset=<bytes> probe at the given offset\n"
			    " --size=<bytes>   overwrite device size\n"
			    " --debug          print debug output to stderr\n"
			    " --help\n\n");
			goto exit;
		default:
			retval = 1;
			goto exit;
		}
	}

	node = argv[optind];
	if (!node) {
		err(udev_ctx, "no device\n");
		fprintf(stderr, "no device\n");
		rc = 1;
		goto exit;
	}

	fd = open(node, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "%s: error opening volume\n", node);
		rc = 2;
		goto exit;
	}

	vid = volume_id_open_fd(fd);
	if (vid == NULL) {
		rc = 2;
		goto exit;
	}

	if (size == 0) {
		if (ioctl(fd, BLKGETSIZE64, &size) != 0)
			size = 0;
		info(udev_ctx, "BLKGETSIZE64=%" PRIu64 " (%" PRIu64 "GB)\n", size, size >> 30);
	}

	/* try to drop all privileges before reading disk content */
	if (getuid() == 0) {
		struct passwd *pw;

		pw = getpwnam("nobody");
		if (pw != NULL && pw->pw_uid > 0 && pw->pw_gid > 0) {
			if (setgroups(0, NULL) != 0 ||
			    setgid(pw->pw_gid) != 0 ||
			    setuid(pw->pw_uid) != 0)
				info(udev_ctx, "unable to drop privileges: %s\n\n", strerror(errno));
		}
	}

	if (probe_all) {
		volume_id_all_probers(all_probers, vid, offset, size, NULL);
		goto exit;
	}

	if (skip_raid)
		retval = volume_id_probe_filesystem(vid, offset, size);
	else
		retval = volume_id_probe_all(vid, offset, size);
	if (retval != 0) {
		fprintf(stderr, "%s: unknown volume type\n", node);
		rc = 4;
		goto exit;
	}

	if (!volume_id_get_label(vid, &label) ||
	    !volume_id_get_usage(vid, &usage) ||
	    !volume_id_get_type(vid, &type) ||
	    !volume_id_get_type_version(vid, &type_version) ||
	    !volume_id_get_uuid(vid, &uuid)) {
		rc = 4;
		goto exit;
	}

	set_str(label_safe, label, sizeof(label_safe));
	util_replace_chars(label_safe, ALLOWED_CHARS_INPUT);
	volume_id_encode_string(label, label_enc, sizeof(label_enc));

	set_str(uuid_safe, uuid, sizeof(uuid_safe));
	util_replace_chars(uuid_safe, ALLOWED_CHARS_INPUT);
	volume_id_encode_string(uuid, uuid_enc, sizeof(uuid_enc));

	volume_id_encode_string(type, type_enc, sizeof(type_enc));
	volume_id_encode_string(type_version, type_version_enc, sizeof(type_version_enc));

	switch (print) {
	case PRINT_EXPORT:
		printf("ID_FS_USAGE=%s\n", usage);
		printf("ID_FS_TYPE=%s\n", type_enc);
		printf("ID_FS_VERSION=%s\n", type_version_enc);
		printf("ID_FS_UUID=%s\n", uuid_safe);
		printf("ID_FS_UUID_ENC=%s\n", uuid_enc);
		printf("ID_FS_LABEL=%s\n", label_safe);
		printf("ID_FS_LABEL_ENC=%s\n", label_enc);
		break;
	case PRINT_TYPE:
		printf("%s\n", type);
		break;
	case PRINT_LABEL:
		if (label_safe[0] == '\0' || strcmp(usage, "raid") == 0) {
			rc = 3;
			goto exit;
		}
		printf("%s\n", label_safe);
		break;
	case PRINT_UUID:
		if (uuid_enc[0] == '\0' || strcmp(usage, "raid") == 0) {
			rc = 4;
			goto exit;
		}
		printf("%s\n", uuid_enc);
		break;
	case PRINT_LABEL_RAW:
		if (label[0] == '\0' || strcmp(usage, "raid") == 0) {
			rc = 3;
			goto exit;
		}
		printf("%s\n", label);
		break;
	}

exit:
	if (vid != NULL)
		volume_id_close(vid);
	udev_unref(udev_ctx);
	logging_close();
	return rc;
}
