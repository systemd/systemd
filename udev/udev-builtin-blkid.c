/*
 * probe disks for filesystems and partitions
 *
 * Copyright (C) 2011 Kay Sievers <kay.sievers@vrfy.org>
 * Copyright (C) 2011 Karel Zak <kzak@redhat.com>
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
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <blkid/blkid.h>

#include "udev.h"

static void print_property(const char *name, const char *value)
{
	char enc[265], safe[256];
	size_t namelen = strlen(name);

	enc[0] = '\0';
	safe[0] = '\0';

	if (!strcmp(name, "TYPE") || !strcmp(name, "VERSION")) {
		blkid_encode_string(value, enc, sizeof(enc));
		printf("ID_FS_%s=%s\n", name, enc);

	} else if (!strcmp(name, "UUID") ||
		 !strcmp(name, "LABEL") ||
		 !strcmp(name, "UUID_SUB")) {

		blkid_safe_string(value, safe, sizeof(safe));
		printf("ID_FS_%s=%s\n", name, safe);

		blkid_encode_string(value, enc, sizeof(enc));
		printf("ID_FS_%s_ENC=%s\n", name, enc);

	} else if (!strcmp(name, "PTTYPE")) {
		printf("ID_PART_TABLE_TYPE=%s\n", value);

	} else if (!strcmp(name, "PART_ENTRY_NAME") ||
		  !strcmp(name, "PART_ENTRY_TYPE")) {

		blkid_encode_string(value, enc, sizeof(enc));
		printf("ID_%s=%s\n", name, enc);

	} else if (!strncmp(name, "PART_ENTRY_", 11))
		printf("ID_%s=%s\n", name, value);

	else if (namelen >= 15 && (
		   !strcmp(name + (namelen - 12), "_SECTOR_SIZE") ||
		   !strcmp(name + (namelen - 8), "_IO_SIZE") ||
		   !strcmp(name, "ALIGNMENT_OFFSET")))
			printf("ID_IOLIMIT_%s=%s\n", name, value);
	else
		printf("ID_FS_%s=%s\n", name, value);
}

static int probe_superblocks(blkid_probe pr)
{
	struct stat st;
	int rc;

	if (fstat(blkid_probe_get_fd(pr), &st))
		return -1;

	blkid_probe_enable_partitions(pr, 1);

	if (!S_ISCHR(st.st_mode) && blkid_probe_get_size(pr) <= 1024 * 1440 &&
	    blkid_probe_is_wholedisk(pr)) {
		/*
		 * check if the small disk is partitioned, if yes then
		 * don't probe for filesystems.
		 */
		blkid_probe_enable_superblocks(pr, 0);

		rc = blkid_do_fullprobe(pr);
		if (rc < 0)
			return rc;	/* -1 = error, 1 = nothing, 0 = succes */

		if (blkid_probe_lookup_value(pr, "PTTYPE", NULL, NULL) == 0)
			return 0;	/* partition table detected */
	}

	blkid_probe_set_partitions_flags(pr, BLKID_PARTS_ENTRY_DETAILS);
	blkid_probe_enable_superblocks(pr, 1);

	return blkid_do_safeprobe(pr);
}

static int builtin_blkid(struct udev_device *dev, int argc, char *argv[], bool test)
{
	char *device = "/dev/sda3";
	int64_t offset = 0;
	//int noraid = 0;
	int fd = -1;
	blkid_probe pr;
	const char *data;
	const char *name;
	int nvals;
	int i;
	size_t len;
	int err = 0;

	//FIXME: read offset, read noraid

	pr = blkid_new_probe();
	if (!pr) {
		err = -ENOMEM;
		return EXIT_FAILURE;
	}

	blkid_probe_set_superblocks_flags(pr,
		BLKID_SUBLKS_LABEL | BLKID_SUBLKS_UUID |
		BLKID_SUBLKS_TYPE | BLKID_SUBLKS_SECTYPE |
		BLKID_SUBLKS_USAGE | BLKID_SUBLKS_VERSION);

	fd = open(device, O_RDONLY|O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "error: %s: %m\n", device);
		goto out;
	}

	err = blkid_probe_set_device(pr, fd, offset, 0);
	if (err < 0)
		goto out;

	err = probe_superblocks(pr);
	if (err < 0)
		goto out;

	nvals = blkid_probe_numof_values(pr);
	for (i = 0; i < nvals; i++) {
		if (blkid_probe_get_value(pr, i, &name, &data, &len))
			continue;
		len = strnlen((char *) data, len);
		print_property(name, (char *) data);
	}

	blkid_free_probe(pr);
out:
	if (fd > 0)
		close(fd);
	if (err < 0)
		return EXIT_FAILURE;
	return EXIT_SUCCESS;
}

const struct udev_builtin udev_builtin_blkid = {
	.name = "blkid",
	.cmd = builtin_blkid,
	.help = "filesystem and partition probing",
	.run_once = true,
};
