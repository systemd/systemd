/*
 * volume_id - reads filesystem label and uuid
 *
 * Copyright (C) 2004 Kay Sievers <kay.sievers@vrfy.org>
 * Copyright (C) 2005 Tobias Klauser <tklauser@access.unizh.ch>
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#include "libvolume_id.h"
#include "util.h"

struct reiserfs_super_block {
	uint32_t	blocks_count;
	uint32_t	free_blocks;
	uint32_t	root_block;
	uint32_t	journal_block;
	uint32_t	journal_dev;
	uint32_t	orig_journal_size;
	uint32_t	dummy2[5];
	uint16_t	blocksize;
	uint16_t	dummy3[3];
	uint8_t		magic[12];
	uint32_t	dummy4[5];
	uint8_t		uuid[16];
	uint8_t		label[16];
} PACKED;

struct reiser4_super_block {
	uint8_t		magic[16];
	uint16_t	dummy[2];
	uint8_t		uuid[16];
	uint8_t		label[16];
	uint64_t	dummy2;
} PACKED;

#define REISERFS1_SUPERBLOCK_OFFSET		0x2000
#define REISERFS_SUPERBLOCK_OFFSET		0x10000

int volume_id_probe_reiserfs(struct volume_id *id, uint64_t off, uint64_t size)
{
	struct reiserfs_super_block *rs;
	struct reiser4_super_block *rs4;
	uint8_t	 *buf;

	info("probing at offset 0x%llx", (unsigned long long) off);

	buf = volume_id_get_buffer(id, off + REISERFS_SUPERBLOCK_OFFSET, 0x200);
	if (buf == NULL)
		return -1;

	rs = (struct reiserfs_super_block *) buf;
	if (memcmp(rs->magic, "ReIsErFs", 8) == 0) {
		strcpy(id->type_version, "3.5");
		id->type = "reiserfs";
		goto found;
	}
	if (memcmp(rs->magic, "ReIsEr2Fs", 9) == 0) {
		strcpy(id->type_version, "3.6");
		id->type = "reiserfs";
		goto found_label;
	}
	if (memcmp(rs->magic, "ReIsEr3Fs", 9) == 0) {
		strcpy(id->type_version, "JR");
		id->type = "reiserfs";
		goto found_label;
	}

	rs4 = (struct reiser4_super_block *) buf;
	if (memcmp(rs4->magic, "ReIsEr4", 7) == 0) {
		strcpy(id->type_version, "4");
		volume_id_set_label_raw(id, rs4->label, 16);
		volume_id_set_label_string(id, rs4->label, 16);
		volume_id_set_uuid(id, rs4->uuid, UUID_DCE);
		id->type = "reiser4";
		goto found;
	}

	buf = volume_id_get_buffer(id, off + REISERFS1_SUPERBLOCK_OFFSET, 0x200);
	if (buf == NULL)
		return -1;

	rs = (struct reiserfs_super_block *) buf;
	if (memcmp(rs->magic, "ReIsErFs", 8) == 0) {
		strcpy(id->type_version, "3.5");
		id->type = "reiserfs";
		goto found;
	}

	return -1;

found_label:
	volume_id_set_label_raw(id, rs->label, 16);
	volume_id_set_label_string(id, rs->label, 16);
	volume_id_set_uuid(id, rs->uuid, UUID_DCE);

found:
	volume_id_set_usage(id, VOLUME_ID_FILESYSTEM);

	return 0;
}
