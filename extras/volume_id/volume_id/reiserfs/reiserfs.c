/*
 * volume_id - reads filesystem label and uuid
 *
 * Copyright (C) 2004 Kay Sievers <kay.sievers@vrfy.org>
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation; either
 *	version 2.1 of the License, or (at your option) any later version.
 *
 *	This library is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *	Lesser General Public License for more details.
 *
 *	You should have received a copy of the GNU Lesser General Public
 *	License along with this library; if not, write to the Free Software
 *	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
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
#include <asm/types.h>

#include "../volume_id.h"
#include "../logging.h"
#include "../util.h"
#include "reiserfs.h"

struct reiserfs_super_block {
	__u32	blocks_count;
	__u32	free_blocks;
	__u32	root_block;
	__u32	journal_block;
	__u32	journal_dev;
	__u32	orig_journal_size;
	__u32	dummy2[5];
	__u16	blocksize;
	__u16	dummy3[3];
	__u8	magic[12];
	__u32	dummy4[5];
	__u8	uuid[16];
	__u8	label[16];
} __attribute__((__packed__));

#define REISERFS1_SUPERBLOCK_OFFSET		0x2000
#define REISERFS_SUPERBLOCK_OFFSET		0x10000

int volume_id_probe_reiserfs(struct volume_id *id, __u64 off)
{
	struct reiserfs_super_block *rs;

	dbg("probing at offset %llu", off);

	rs = (struct reiserfs_super_block *) volume_id_get_buffer(id, off + REISERFS_SUPERBLOCK_OFFSET, 0x200);
	if (rs == NULL)
		return -1;

	if (memcmp(rs->magic, "ReIsEr2Fs", 9) == 0) {
		strcpy(id->type_version, "3.6");
		goto found;
	}

	if (memcmp(rs->magic, "ReIsEr3Fs", 9) == 0) {
		strcpy(id->type_version, "JR");
		goto found;
	}

	rs = (struct reiserfs_super_block *) volume_id_get_buffer(id, off + REISERFS1_SUPERBLOCK_OFFSET, 0x200);
	if (rs == NULL)
		return -1;

	if (memcmp(rs->magic, "ReIsErFs", 8) == 0) {
		strcpy(id->type_version, "3.5");
		goto found;
	}

	return -1;

found:
	volume_id_set_label_raw(id, rs->label, 16);
	volume_id_set_label_string(id, rs->label, 16);
	volume_id_set_uuid(id, rs->uuid, UUID_DCE);

	volume_id_set_usage(id, VOLUME_ID_FILESYSTEM);
	id->type = "reiserfs";

	return 0;
}
