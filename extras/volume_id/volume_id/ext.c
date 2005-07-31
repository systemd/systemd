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

#include "volume_id.h"
#include "util.h"
#include "logging.h"
#include "ext.h"

struct ext2_super_block {
	uint32_t	inodes_count;
	uint32_t	blocks_count;
	uint32_t	r_blocks_count;
	uint32_t	free_blocks_count;
	uint32_t	free_inodes_count;
	uint32_t	first_data_block;
	uint32_t	log_block_size;
	uint32_t	dummy3[7];
	uint8_t	magic[2];
	uint16_t	state;
	uint32_t	dummy5[8];
	uint32_t	feature_compat;
	uint32_t	feature_incompat;
	uint32_t	feature_ro_compat;
	uint8_t	uuid[16];
	uint8_t	volume_name[16];
} __attribute__((__packed__));

#define EXT3_FEATURE_COMPAT_HAS_JOURNAL		0x00000004
#define EXT3_FEATURE_INCOMPAT_JOURNAL_DEV	0x00000008
#define EXT_SUPERBLOCK_OFFSET			0x400

int volume_id_probe_ext(struct volume_id *id, uint64_t off)
{
	struct ext2_super_block *es;

	dbg("probing at offset 0x%llx", (unsigned long long) off);

	es = (struct ext2_super_block *) volume_id_get_buffer(id, off + EXT_SUPERBLOCK_OFFSET, 0x200);
	if (es == NULL)
		return -1;

	if (es->magic[0] != 0123 ||
	    es->magic[1] != 0357)
		return -1;

	volume_id_set_usage(id, VOLUME_ID_FILESYSTEM);
	volume_id_set_label_raw(id, es->volume_name, 16);
	volume_id_set_label_string(id, es->volume_name, 16);
	volume_id_set_uuid(id, es->uuid, UUID_DCE);

	if ((le32_to_cpu(es->feature_compat) & EXT3_FEATURE_COMPAT_HAS_JOURNAL) != 0)
		id->type = "ext3";
	else
		id->type = "ext2";

	return 0;
}
