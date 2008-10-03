/*
 * volume_id - reads filesystem label and uuid
 *
 * Copyright (C) 2006 Kay Sievers <kay.sievers@vrfy.org>
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
#include <errno.h>
#include <ctype.h>

#include "libvolume_id.h"
#include "libvolume_id-private.h"

#define SQUASHFS_MAGIC		0x73717368
#define SQUASHFS_MAGIC_LZMA	0x71736873

struct squashfs_super {
	uint32_t	s_magic;
	uint32_t	inodes;
	uint32_t	bytes_used_2;
	uint32_t	uid_start_2;
	uint32_t	guid_start_2;
	uint32_t	inode_table_start_2;
	uint32_t	directory_table_start_2;
	uint16_t	s_major;
	uint16_t	s_minor;
} PACKED;

int volume_id_probe_squashfs(struct volume_id *id, uint64_t off, uint64_t size)
{
	struct squashfs_super *sqs;

	info("probing at offset 0x%" PRIx64 "\n", off);

	sqs = (struct squashfs_super *) volume_id_get_buffer(id, off, 0x200);
	if (sqs == NULL)
		return -1;

	if (sqs->s_magic == SQUASHFS_MAGIC || sqs->s_magic == SQUASHFS_MAGIC_LZMA) {
		snprintf(id->type_version, sizeof(id->type_version), "%u.%u",
			 sqs->s_major, sqs->s_minor);
		goto found;
	}
	if (sqs->s_magic == bswap_32(SQUASHFS_MAGIC) || sqs->s_magic == bswap_32(SQUASHFS_MAGIC_LZMA)) {
		snprintf(id->type_version, sizeof(id->type_version), "%u.%u",
			 bswap_16(sqs->s_major), bswap_16(sqs->s_minor));
		goto found;
	}

	return -1;

found:
	volume_id_set_usage(id, VOLUME_ID_FILESYSTEM);
	id->type = "squashfs";
	return 0;
}
