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

#include "volume_id.h"
#include "util.h"
#include "logging.h"
#include "ext.h"

struct ext2_super_block {
	__u32	inodes_count;
	__u32	blocks_count;
	__u32	r_blocks_count;
	__u32	free_blocks_count;
	__u32	free_inodes_count;
	__u32	first_data_block;
	__u32	log_block_size;
	__u32	dummy3[7];
	__u8	magic[2];
	__u16	state;
	__u32	dummy5[8];
	__u32	feature_compat;
	__u32	feature_incompat;
	__u32	feature_ro_compat;
	__u8	uuid[16];
	__u8	volume_name[16];
} __attribute__((__packed__));

#define EXT3_FEATURE_COMPAT_HAS_JOURNAL		0x00000004
#define EXT3_FEATURE_INCOMPAT_JOURNAL_DEV	0x00000008
#define EXT_SUPERBLOCK_OFFSET			0x400

int volume_id_probe_ext(struct volume_id *id, __u64 off)
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
