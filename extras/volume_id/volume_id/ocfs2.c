/*
 * volume_id - reads filesystem label and uuid
 *
 * Copyright (C) Andre Masella <andre@masella.no-ip.org>
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
#include "logging.h"
#include "util.h"
#include "ocfs2.h"


/* All these values are taken from ocfs2-tools's ocfs2_fs.h */
#define OCFS2_VOL_UUID_LEN			16
#define OCFS2_MAX_VOL_LABEL_LEN			64
#define OCFS2_SUPERBLOCK_OFFSET			0x2000


/* This is the superblock. The OCFS2 header files have structs in structs.
This is one has been simplified since we only care about the superblock.
*/

struct ocfs2_super_block {
	__u8 i_signature[8];			/* Signature for validation */
	__u32 i_generation;			/* Generation number */
	__s16 i_suballoc_slot;			/* Slot suballocator this inode belongs to */
	__u16 i_suballoc_bit;			/* Bit offset in suballocator block group */
	__u32 i_reserved0;
	__u32 i_clusters;			/* Cluster count */
	__u32 i_uid;				/* Owner UID */
	__u32 i_gid;				/* Owning GID */
	__u64 i_size;				/* Size in bytes */
	__u16 i_mode;				/* File mode */
	__u16 i_links_count;			/* Links count */
	__u32 i_flags;				/* File flags */
	__u64 i_atime;				/* Access time */
	__u64 i_ctime;				/* Creation time */
	__u64 i_mtime;				/* Modification time */
	__u64 i_dtime;				/* Deletion time */
	__u64 i_blkno;				/* Offset on disk, in blocks */
	__u64 i_last_eb_blk;			/* Pointer to last extent block */
	__u32 i_fs_generation;			/* Generation per fs-instance */
	__u32 i_atime_nsec;
	__u32 i_ctime_nsec;
	__u32 i_mtime_nsec;
	__u64 i_reserved1[9];
	__u64 i_pad1;				/* Generic way to refer to this 64bit union */
	/* Normally there is a union of the different block types, but we only care about the superblock. */
	__u16 s_major_rev_level;
	__u16 s_minor_rev_level;
	__u16 s_mnt_count;
	__s16 s_max_mnt_count;
	__u16 s_state;				/* File system state */
	__u16 s_errors;				/* Behaviour when detecting errors */
	__u32 s_checkinterval;			/* Max time between checks */
	__u64 s_lastcheck;			/* Time of last check */
	__u32 s_creator_os;			/* OS */
	__u32 s_feature_compat;			/* Compatible feature set */
	__u32 s_feature_incompat;		/* Incompatible feature set */
	__u32 s_feature_ro_compat;		/* Readonly-compatible feature set */
	__u64 s_root_blkno;			/* Offset, in blocks, of root directory dinode */
	__u64 s_system_dir_blkno;		/* Offset, in blocks, of system directory dinode */
	__u32 s_blocksize_bits;			/* Blocksize for this fs */
	__u32 s_clustersize_bits;		/* Clustersize for this fs */
	__u16 s_max_slots;			/* Max number of simultaneous mounts before tunefs required */
	__u16 s_reserved1;
	__u32 s_reserved2;
	__u64 s_first_cluster_group;		/* Block offset of 1st cluster group header */
	__u8  s_label[OCFS2_MAX_VOL_LABEL_LEN];	/* Label for mounting, etc. */
	__u8  s_uuid[OCFS2_VOL_UUID_LEN];	/* 128-bit uuid */
} __attribute__((__packed__));

int volume_id_probe_ocfs2(struct volume_id *id, __u64 off)
{
	struct ocfs2_super_block *os;

	dbg("probing at offset 0x%llx", (unsigned long long) off);

	os = (struct ocsf2_super_block *) volume_id_get_buffer(id, off + OCFS2_SUPERBLOCK_OFFSET, 0x200);
	if (os == NULL)
		return -1;

	if (strcmp(os->i_signature, "OCFSV2") != 0) {
		return -1;
	}

	volume_id_set_usage(id, VOLUME_ID_FILESYSTEM);
	volume_id_set_label_raw(id, os->s_label, OCFS2_MAX_VOL_LABEL_LEN < VOLUME_ID_LABEL_SIZE ?
					OCFS2_MAX_VOL_LABEL_LEN : VOLUME_ID_LABEL_SIZE);
	volume_id_set_label_string(id, os->s_label, OCFS2_MAX_VOL_LABEL_LEN < VOLUME_ID_LABEL_SIZE ?
					OCFS2_MAX_VOL_LABEL_LEN : VOLUME_ID_LABEL_SIZE);
	volume_id_set_uuid(id, os->s_uuid, UUID_DCE);
	id->type = "ocfs2";
	return 0;
}
