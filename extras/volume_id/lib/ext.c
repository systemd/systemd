/*
 * volume_id - reads filesystem label and uuid
 *
 * Copyright (C) 2004 Kay Sievers <kay.sievers@vrfy.org>
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

struct ext2_super_block {
	uint32_t	s_inodes_count;
	uint32_t	s_blocks_count;
	uint32_t	s_r_blocks_count;
	uint32_t	s_free_blocks_count;
	uint32_t	s_free_inodes_count;
	uint32_t	s_first_data_block;
	uint32_t	s_log_block_size;
	uint32_t	s_log_frag_size;
	uint32_t	s_blocks_per_group;
	uint32_t	s_frags_per_group;
	uint32_t	s_inodes_per_group;
	uint32_t	s_mtime;
	uint32_t	s_wtime;
	uint16_t	s_mnt_count;
	uint16_t	s_max_mnt_count;
	uint16_t	s_magic;
	uint16_t	s_state;
	uint16_t	s_errors;
	uint16_t	s_minor_rev_level;
	uint32_t	s_lastcheck;
	uint32_t	s_checkinterval;
	uint32_t	s_creator_os;
	uint32_t	s_rev_level;
	uint16_t	s_def_resuid;
	uint16_t	s_def_resgid;
	uint32_t	s_first_ino;
	uint16_t	s_inode_size;
	uint16_t	s_block_group_nr;
	uint32_t	s_feature_compat;
	uint32_t	s_feature_incompat;
	uint32_t	s_feature_ro_compat;
	uint8_t		s_uuid[16];
	uint8_t		s_volume_name[16];
} PACKED;

#define EXT_SUPER_MAGIC				0xEF53
#define EXT3_FEATURE_COMPAT_HAS_JOURNAL		0x00000004
#define EXT3_FEATURE_INCOMPAT_JOURNAL_DEV	0x00000008
#define EXT_SUPERBLOCK_OFFSET			0x400

#define EXT3_MIN_BLOCK_SIZE			0x400
#define EXT3_MAX_BLOCK_SIZE			0x1000

int volume_id_probe_ext(struct volume_id *id, uint64_t off, uint64_t size)
{
	struct ext2_super_block *es;
	size_t bsize;

	info("probing at offset 0x%llx", (unsigned long long) off);

	es = (struct ext2_super_block *) volume_id_get_buffer(id, off + EXT_SUPERBLOCK_OFFSET, 0x200);
	if (es == NULL)
		return -1;

	if (es->s_magic != cpu_to_le16(EXT_SUPER_MAGIC))
		return -1;

	bsize = 0x400 << le32_to_cpu(es->s_log_block_size);
	dbg("ext blocksize 0x%zx", bsize);
	if (bsize < EXT3_MIN_BLOCK_SIZE || bsize > EXT3_MAX_BLOCK_SIZE) {
		dbg("invalid ext blocksize");
		return -1;
	}

	volume_id_set_label_raw(id, es->s_volume_name, 16);
	volume_id_set_label_string(id, es->s_volume_name, 16);
	volume_id_set_uuid(id, es->s_uuid, UUID_DCE);
	snprintf(id->type_version, sizeof(id->type_version)-1,
		 "%u.%u", es->s_rev_level, es->s_minor_rev_level);

	/* check for external journal device */
	if ((le32_to_cpu(es->s_feature_incompat) & EXT3_FEATURE_INCOMPAT_JOURNAL_DEV) != 0) {
		volume_id_set_usage(id, VOLUME_ID_OTHER);
		id->type = "jbd";
		return 0;
	}

	/* check for ext2 / ext3 */
	volume_id_set_usage(id, VOLUME_ID_FILESYSTEM);
	if ((le32_to_cpu(es->s_feature_compat) & EXT3_FEATURE_COMPAT_HAS_JOURNAL) != 0)
		id->type = "ext3";
	else
		id->type = "ext2";

	return 0;
}
