/*
 * vol_id - read filesystem label and uuid
 *
 * Copyright (C) 2005-2006 Kay Sievers <kay.sievers@vrfy.org>
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
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <getopt.h>
#include <sys/ioctl.h>

#include "../../udev.h"
#include "lib/libvolume_id.h"

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

static void vid_log(int priority, const char *file, int line, const char *format, ...)
{
#ifdef USE_LOG
	char log_str[1024];
	va_list args;

	va_start(args, format);
	vsnprintf(log_str, sizeof(log_str), format, args);
	log_str[sizeof(log_str)-1] = '\0';
	log_message(priority, "%s:%i %s", file, line, log_str);
	va_end(args);
#endif
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

int main(int argc, char *argv[])
{
	static const struct option options[] = {
		{ "label", 0, NULL, 'l' },
		{ "label-raw", 0, NULL, 'L' },
		{ "uuid", 0, NULL, 'u' },
		{ "type", 0, NULL, 't' },
		{ "export", 0, NULL, 'x' },
		{ "skip-raid", 0, NULL, 's' },
		{ "probe-all", 0, NULL, 'a' },
		{ "help", 0, NULL, 'h' },
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
	static char name[VOLUME_ID_LABEL_SIZE];
	uint64_t size;
	int skip_raid = 0;
	int probe_all = 0;
	const char *node;
	struct passwd *pw;
	int retval;
	int rc = 0;

	logging_init("vol_id");

	/* hook in our debug into libvolume_id */
	volume_id_log_fn = vid_log;

	while (1) {
		int option;

		option = getopt_long(argc, argv, "lLutxsah", options, NULL);
		if (option == -1)
			break;

		switch (option) {
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
		case 'h':
			printf("Usage: vol_id [options] <device>\n"
			    " --export        export key/value pairs\n"
			    " --type          filesystem type\n"
			    " --label         filesystem label\n"
			    " --label-raw     raw label\n"
			    " --uuid          filesystem uuid\n"
			    " --skip-raid     don't probe for raid\n"
			    " --probe-all     find possibly conflicting signatures\n"
			    " --help\n\n");
			goto exit;
		default:
			retval = 1;
			goto exit;
		}
	}

	node = argv[optind];
	if (!node) {
		err("no device");
		fprintf(stderr, "no device\n");
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
	dbg("BLKGETSIZE64=%llu", (unsigned long long)size);

	/* try to drop all privileges before reading disk content */
	pw = getpwnam ("nobody");
	if (pw != NULL && pw->pw_uid > 0 && pw->pw_gid > 0) {
		dbg("dropping privileges to %u:%u",
		    (unsigned int)pw->pw_uid, (unsigned int)pw->pw_gid);
		if (setgroups(0, NULL) != 0 ||
		    setgid(pw->pw_gid) != 0 ||
		    setuid(pw->pw_uid) != 0) {
			fprintf(stderr, "error dropping privileges: %s\n", strerror(errno));
			rc = 3;
			goto exit;
		}
	}

	if (probe_all) {
		if (volume_id_probe_linux_raid(vid, 0, size) == 0)
			printf("%s\n", vid->type);
		if (volume_id_probe_intel_software_raid(vid, 0, size) == 0)
			printf("%s\n", vid->type);
		if (volume_id_probe_lsi_mega_raid(vid, 0, size) == 0)
			printf("%s\n", vid->type);
		if (volume_id_probe_via_raid(vid, 0, size) == 0)
			printf("%s\n", vid->type);
		if (volume_id_probe_silicon_medley_raid(vid, 0, size) == 0)
			printf("%s\n", vid->type);
		if (volume_id_probe_nvidia_raid(vid, 0, size) == 0)
			printf("%s\n", vid->type);
		if (volume_id_probe_promise_fasttrack_raid(vid, 0, size) == 0)
			printf("%s\n", vid->type);
		if (volume_id_probe_highpoint_45x_raid(vid, 0, size) == 0)
			printf("%s\n", vid->type);
		if (volume_id_probe_adaptec_raid(vid, 0, size) == 0)
			printf("%s\n", vid->type);
		if (volume_id_probe_jmicron_raid(vid, 0, size) == 0)
			printf("%s\n", vid->type);
		if (volume_id_probe_vfat(vid, 0, 0) == 0)
			printf("%s\n", vid->type);
		if (volume_id_probe_linux_swap(vid, 0, 0) == 0)
			printf("%s\n", vid->type);
		if (volume_id_probe_luks(vid, 0, 0) == 0)
			printf("%s\n", vid->type);
		if (volume_id_probe_xfs(vid, 0, 0) == 0)
			printf("%s\n", vid->type);
		if (volume_id_probe_ext(vid, 0, 0) == 0)
			printf("%s\n", vid->type);
		if (volume_id_probe_reiserfs(vid, 0, 0) == 0)
			printf("%s\n", vid->type);
		if (volume_id_probe_jfs(vid, 0, 0) == 0)
			printf("%s\n", vid->type);
		if (volume_id_probe_udf(vid, 0, 0) == 0)
			printf("%s\n", vid->type);
		if (volume_id_probe_iso9660(vid, 0, 0) == 0)
			printf("%s\n", vid->type);
		if (volume_id_probe_hfs_hfsplus(vid, 0, 0) == 0)
			printf("%s\n", vid->type);
		if (volume_id_probe_ufs(vid, 0, 0) == 0)
			printf("%s\n", vid->type);
		if (volume_id_probe_ntfs(vid, 0, 0)  == 0)
			printf("%s\n", vid->type);
		if (volume_id_probe_cramfs(vid, 0, 0) == 0)
			printf("%s\n", vid->type);
		if (volume_id_probe_romfs(vid, 0, 0) == 0)
			printf("%s\n", vid->type);
		if (volume_id_probe_hpfs(vid, 0, 0) == 0)
			printf("%s\n", vid->type);
		if (volume_id_probe_sysv(vid, 0, 0) == 0)
			printf("%s\n", vid->type);
		if (volume_id_probe_minix(vid, 0, 0) == 0)
			printf("%s\n", vid->type);
		if (volume_id_probe_ocfs1(vid, 0, 0) == 0)
			printf("%s\n", vid->type);
		if (volume_id_probe_ocfs2(vid, 0, 0) == 0)
			printf("%s\n", vid->type);
		if (volume_id_probe_vxfs(vid, 0, 0) == 0)
			printf("%s\n", vid->type);
		if (volume_id_probe_squashfs(vid, 0, 0) == 0)
			printf("%s\n", vid->type);
		if (volume_id_probe_netware(vid, 0, 0) == 0)
			printf("%s\n", vid->type);
		if (volume_id_probe_gfs(vid, 0, 0) == 0)
			printf("%s\n", vid->type);
		if (volume_id_probe_gfs2(vid, 0, 0) == 0)
			printf("%s\n", vid->type);

		goto exit;
	}

	if (skip_raid)
		retval = volume_id_probe_filesystem(vid, 0, size);
	else
		retval = volume_id_probe_all(vid, 0, size);
	if (retval != 0) {
		fprintf(stderr, "%s: unknown volume type\n", node);
		rc = 4;
		goto exit;
	}

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
		if (name[0] == '\0' || vid->usage_id == VOLUME_ID_RAID) {
			rc = 3;
			goto exit;
		}
		printf("%s\n", name);
		break;
	case PRINT_UUID:
		if (vid->uuid[0] == '\0' || vid->usage_id == VOLUME_ID_RAID) {
			rc = 4;
			goto exit;
		}
		printf("%s\n", vid->uuid);
		break;
	case PRINT_LABEL_RAW:
		if (vid->label[0] == '\0' || vid->usage_id == VOLUME_ID_RAID) {
			rc = 3;
			goto exit;
		}
		printf("%s\n", vid->label);
		break;
	}

exit:
	if (vid != NULL)
		volume_id_close(vid);

	logging_close();
	return rc;
}
