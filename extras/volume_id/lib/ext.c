/*
 * volume_id - reads filesystem label and uuid
 *
 * Copyright (C) 2004-2008 Kay Sievers <kay.sievers@vrfy.org>
 * Copyright (C) 2008 Theodore Ts'o <tytso@mit.edu>
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
	uint8_t		s_last_mounted[64];
	uint32_t	s_algorithm_usage_bitmap;
	uint8_t		s_prealloc_blocks;
	uint8_t		s_prealloc_dir_blocks;
	uint16_t	s_reserved_gdt_blocks;
	uint8_t		s_journal_uuid[16];
	uint32_t	s_journal_inum;
	uint32_t	s_journal_dev;
	uint32_t	s_last_orphan;
	uint32_t	s_hash_seed[4];
	uint8_t		s_def_hash_version;
	uint8_t		s_jnl_backup_type;
	uint16_t	s_reserved_word_pad;
	uint32_t	s_default_mount_opts;
	uint32_t	s_first_meta_bg;
	uint32_t	s_mkfs_time;
	uint32_t	s_jnl_blocks[17];
	uint32_t	s_blocks_count_hi;
	uint32_t	s_r_blocks_count_hi;
	uint32_t	s_free_blocks_hi;
	uint16_t	s_min_extra_isize;
	uint16_t	s_want_extra_isize;
	uint32_t	s_flags;
} PACKED;

#define EXT_SUPER_MAGIC				0xEF53
#define EXT2_FLAGS_TEST_FILESYS			0x0004
#define EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER	0x0001
#define EXT2_FEATURE_RO_COMPAT_LARGE_FILE	0x0002
#define EXT2_FEATURE_RO_COMPAT_BTREE_DIR	0x0004
#define EXT2_FEATURE_INCOMPAT_FILETYPE		0x0002
#define EXT2_FEATURE_INCOMPAT_META_BG		0x0010
#define EXT3_FEATURE_COMPAT_HAS_JOURNAL		0x0004
#define EXT3_FEATURE_INCOMPAT_JOURNAL_DEV	0x0008
#define EXT3_FEATURE_INCOMPAT_RECOVER		0x0004


#define EXT2_FEATURE_RO_COMPAT_SUPP	(EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER| \
					 EXT2_FEATURE_RO_COMPAT_LARGE_FILE| \
					 EXT2_FEATURE_RO_COMPAT_BTREE_DIR)
#define EXT2_FEATURE_RO_COMPAT_UNSUPPORTED	~EXT2_FEATURE_RO_COMPAT_SUPP

#define EXT2_FEATURE_INCOMPAT_SUPP	(EXT2_FEATURE_INCOMPAT_FILETYPE| \
					 EXT2_FEATURE_INCOMPAT_META_BG)
#define EXT2_FEATURE_INCOMPAT_UNSUPPORTED	~EXT2_FEATURE_INCOMPAT_SUPP

#define EXT3_FEATURE_RO_COMPAT_SUPP	(EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER| \
					 EXT2_FEATURE_RO_COMPAT_LARGE_FILE| \
					 EXT2_FEATURE_RO_COMPAT_BTREE_DIR)
#define EXT3_FEATURE_RO_COMPAT_UNSUPPORTED	~EXT3_FEATURE_RO_COMPAT_SUPP

#define EXT3_FEATURE_INCOMPAT_SUPP	(EXT2_FEATURE_INCOMPAT_FILETYPE| \
					 EXT3_FEATURE_INCOMPAT_RECOVER| \
					 EXT2_FEATURE_INCOMPAT_META_BG)
#define EXT3_FEATURE_INCOMPAT_UNSUPPORTED	~EXT3_FEATURE_INCOMPAT_SUPP

#define EXT_SUPERBLOCK_OFFSET			0x400
#define EXT3_MIN_BLOCK_SIZE			0x400
#define EXT3_MAX_BLOCK_SIZE			0x1000

int volume_id_probe_ext(struct volume_id *id, uint64_t off, uint64_t size)
{
	struct ext2_super_block *es;
	size_t bsize;
	uint32_t feature_compat;
	uint32_t feature_ro_compat;
	uint32_t feature_incompat;
	uint32_t flags;

	info("probing at offset 0x%" PRIx64 "\n", off);

	es = (struct ext2_super_block *) volume_id_get_buffer(id, off + EXT_SUPERBLOCK_OFFSET, 0x200);
	if (es == NULL)
		return -1;

	if (es->s_magic != cpu_to_le16(EXT_SUPER_MAGIC))
		return -1;

	bsize = 0x400 << le32_to_cpu(es->s_log_block_size);
	dbg("ext blocksize 0x%zx\n", bsize);
	if (bsize < EXT3_MIN_BLOCK_SIZE || bsize > EXT3_MAX_BLOCK_SIZE) {
		dbg("invalid ext blocksize\n");
		return -1;
	}

	feature_compat = le32_to_cpu(es->s_feature_compat);
	feature_ro_compat = le32_to_cpu(es->s_feature_ro_compat);
	feature_incompat = le32_to_cpu(es->s_feature_incompat);
	flags = le32_to_cpu(es->s_flags);

	/* external journal device is jbd */
	if ((feature_incompat & EXT3_FEATURE_INCOMPAT_JOURNAL_DEV) != 0) {
		volume_id_set_usage(id, VOLUME_ID_OTHER);
		id->type = "jbd";
		goto found;
	}

	/* has journal */
	if ((feature_compat & EXT3_FEATURE_COMPAT_HAS_JOURNAL) != 0) {
		/* "use on development code" is ext4dev */
		if ((flags & EXT2_FLAGS_TEST_FILESYS) != 0) {
			id->type = "ext4dev";
			goto found;
		}

		/* incompatible ext3 features is ext4 */
		if ((feature_ro_compat & EXT3_FEATURE_RO_COMPAT_UNSUPPORTED) != 0 ||
		    (feature_incompat & EXT3_FEATURE_INCOMPAT_UNSUPPORTED) != 0) {
			id->type = "ext4";
			goto found;
		}

		id->type = "ext3";
		goto found;
	} else {
		/* no incompatible ext2 feature is ext2 */
		if ((feature_ro_compat & EXT2_FEATURE_RO_COMPAT_UNSUPPORTED) == 0 &&
		    (feature_incompat & EXT2_FEATURE_INCOMPAT_UNSUPPORTED) == 0) {
			id->type = "ext2";
			goto found;
		}
	}

	return -1;

found:
	volume_id_set_label_raw(id, es->s_volume_name, 16);
	volume_id_set_label_string(id, es->s_volume_name, 16);
	volume_id_set_uuid(id, es->s_uuid, 0, UUID_DCE);
	snprintf(id->type_version, sizeof(id->type_version)-1, "%u.%u",
		 le32_to_cpu(es->s_rev_level), le16_to_cpu(es->s_minor_rev_level));

	volume_id_set_usage(id, VOLUME_ID_FILESYSTEM);
	return 0;
}
