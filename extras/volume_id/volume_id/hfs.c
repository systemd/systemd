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
#include "logging.h"
#include "util.h"
#include "hfs.h"

struct hfs_finder_info{
	__u32	boot_folder;
	__u32	start_app;
	__u32	open_folder;
	__u32	os9_folder;
	__u32	reserved;
	__u32	osx_folder;
	__u8	id[8];
} __attribute__((__packed__));

struct hfs_mdb {
	__u8	signature[2];
	__u32	cr_date;
	__u32	ls_Mod;
	__u16	atrb;
	__u16	nm_fls;
	__u16	vbm_st;
	__u16	alloc_ptr;
	__u16	nm_al_blks;
	__u32	al_blk_size;
	__u32	clp_size;
	__u16	al_bl_st;
	__u32	nxt_cnid;
	__u16	free_bks;
	__u8	label_len;
	__u8	label[27];
	__u32	vol_bkup;
	__u16	vol_seq_num;
	__u32	wr_cnt;
	__u32	xt_clump_size;
	__u32	ct_clump_size;
	__u16	num_root_dirs;
	__u32	file_count;
	__u32	dir_count;
	struct hfs_finder_info finder_info;
	__u8	embed_sig[2];
	__u16	embed_startblock;
	__u16	embed_blockcount;
} __attribute__((__packed__)) *hfs;

struct hfsplus_bnode_descriptor {
	__u32	next;
	__u32	prev;
	__u8	type;
	__u8	height;
	__u16	num_recs;
	__u16	reserved;
} __attribute__((__packed__));

struct hfsplus_bheader_record {
	__u16	depth;
	__u32	root;
	__u32	leaf_count;
	__u32	leaf_head;
	__u32	leaf_tail;
	__u16	node_size;
} __attribute__((__packed__));

struct hfsplus_catalog_key {
	__u16	key_len;
	__u32	parent_id;
	__u16	unicode_len;
	__u8	unicode[255 * 2];
} __attribute__((__packed__));

struct hfsplus_extent {
	__u32 start_block;
	__u32 block_count;
} __attribute__((__packed__));

#define HFSPLUS_EXTENT_COUNT		8
struct hfsplus_fork {
	__u64 total_size;
	__u32 clump_size;
	__u32 total_blocks;
	struct hfsplus_extent extents[HFSPLUS_EXTENT_COUNT];
} __attribute__((__packed__));

struct hfsplus_vol_header {
	__u8	signature[2];
	__u16	version;
	__u32	attributes;
	__u32	last_mount_vers;
	__u32	reserved;
	__u32	create_date;
	__u32	modify_date;
	__u32	backup_date;
	__u32	checked_date;
	__u32	file_count;
	__u32	folder_count;
	__u32	blocksize;
	__u32	total_blocks;
	__u32	free_blocks;
	__u32	next_alloc;
	__u32	rsrc_clump_sz;
	__u32	data_clump_sz;
	__u32	next_cnid;
	__u32	write_count;
	__u64	encodings_bmp;
	struct hfs_finder_info finder_info;
	struct hfsplus_fork alloc_file;
	struct hfsplus_fork ext_file;
	struct hfsplus_fork cat_file;
	struct hfsplus_fork attr_file;
	struct hfsplus_fork start_file;
} __attribute__((__packed__)) *hfsplus;

#define HFS_SUPERBLOCK_OFFSET		0x400
#define HFS_NODE_LEAF			0xff
#define HFSPLUS_POR_CNID		1

int volume_id_probe_hfs_hfsplus(struct volume_id *id, __u64 off)
{
	unsigned int blocksize;
	unsigned int cat_block;
	unsigned int ext_block_start;
	unsigned int ext_block_count;
	int ext;
	unsigned int leaf_node_head;
	unsigned int leaf_node_count;
	unsigned int leaf_node_size;
	unsigned int leaf_block;
	__u64 leaf_off;
	unsigned int alloc_block_size;
	unsigned int alloc_first_block;
	unsigned int embed_first_block;
	unsigned int record_count;
	struct hfsplus_bnode_descriptor *descr;
	struct hfsplus_bheader_record *bnode;
	struct hfsplus_catalog_key *key;
	unsigned int	label_len;
	struct hfsplus_extent extents[HFSPLUS_EXTENT_COUNT];
	const __u8 *buf;

	dbg("probing at offset 0x%llx", (unsigned long long) off);

	buf = volume_id_get_buffer(id, off + HFS_SUPERBLOCK_OFFSET, 0x200);
	if (buf == NULL)
                return -1;

	hfs = (struct hfs_mdb *) buf;
	if (memcmp(hfs->signature, "BD", 2) != 0)
		goto checkplus;

	/* it may be just a hfs wrapper for hfs+ */
	if (memcmp(hfs->embed_sig, "H+", 2) == 0) {
		alloc_block_size = be32_to_cpu(hfs->al_blk_size);
		dbg("alloc_block_size 0x%x", alloc_block_size);

		alloc_first_block = be16_to_cpu(hfs->al_bl_st);
		dbg("alloc_first_block 0x%x", alloc_first_block);

		embed_first_block = be16_to_cpu(hfs->embed_startblock);
		dbg("embed_first_block 0x%x", embed_first_block);

		off += (alloc_first_block * 512) +
		       (embed_first_block * alloc_block_size);
		dbg("hfs wrapped hfs+ found at offset 0x%llx", (unsigned long long) off);

		buf = volume_id_get_buffer(id, off + HFS_SUPERBLOCK_OFFSET, 0x200);
		if (buf == NULL)
			return -1;
		goto checkplus;
	}

	if (hfs->label_len > 0 && hfs->label_len < 28) {
		volume_id_set_label_raw(id, hfs->label, hfs->label_len);
		volume_id_set_label_string(id, hfs->label, hfs->label_len) ;
	}

	volume_id_set_uuid(id, hfs->finder_info.id, UUID_HFS);

	volume_id_set_usage(id, VOLUME_ID_FILESYSTEM);
	id->type = "hfs";

	return 0;

checkplus:
	hfsplus = (struct hfsplus_vol_header *) buf;
	if (memcmp(hfsplus->signature, "H+", 2) == 0)
		goto hfsplus;
	if (memcmp(hfsplus->signature, "HX", 2) == 0)
		goto hfsplus;
	return -1;

hfsplus:
	volume_id_set_uuid(id, hfsplus->finder_info.id, UUID_HFS);

	blocksize = be32_to_cpu(hfsplus->blocksize);
	dbg("blocksize %u", blocksize);

	memcpy(extents, hfsplus->cat_file.extents, sizeof(extents));
	cat_block = be32_to_cpu(extents[0].start_block);
	dbg("catalog start block 0x%x", cat_block);

	buf = volume_id_get_buffer(id, off + (cat_block * blocksize), 0x2000);
	if (buf == NULL)
		goto found;

	bnode = (struct hfsplus_bheader_record *)
		&buf[sizeof(struct hfsplus_bnode_descriptor)];

	leaf_node_head = be32_to_cpu(bnode->leaf_head);
	dbg("catalog leaf node 0x%x", leaf_node_head);

	leaf_node_size = be16_to_cpu(bnode->node_size);
	dbg("leaf node size 0x%x", leaf_node_size);

	leaf_node_count = be32_to_cpu(bnode->leaf_count);
	dbg("leaf node count 0x%x", leaf_node_count);
	if (leaf_node_count == 0)
		goto found;

	leaf_block = (leaf_node_head * leaf_node_size) / blocksize;

	/* get physical location */
	for (ext = 0; ext < HFSPLUS_EXTENT_COUNT; ext++) {
		ext_block_start = be32_to_cpu(extents[ext].start_block);
		ext_block_count = be32_to_cpu(extents[ext].block_count);
		dbg("extent start block 0x%x, count 0x%x", ext_block_start, ext_block_count);

		if (ext_block_count == 0)
			goto found;

		/* this is our extent */
		if (leaf_block < ext_block_count)
			break;

		leaf_block -= ext_block_count;
	}
	if (ext == HFSPLUS_EXTENT_COUNT)
		goto found;
	dbg("found block in extent %i", ext);

	leaf_off = (ext_block_start + leaf_block) * blocksize;

	buf = volume_id_get_buffer(id, off + leaf_off, leaf_node_size);
	if (buf == NULL)
		goto found;

	descr = (struct hfsplus_bnode_descriptor *) buf;
	dbg("descriptor type 0x%x", descr->type);

	record_count = be16_to_cpu(descr->num_recs);
	dbg("number of records %u", record_count);
	if (record_count == 0)
		goto found;

	if (descr->type != HFS_NODE_LEAF)
		goto found;

	key = (struct hfsplus_catalog_key *)
		&buf[sizeof(struct hfsplus_bnode_descriptor)];

	dbg("parent id 0x%x", be32_to_cpu(key->parent_id));
	if (be32_to_cpu(key->parent_id) != HFSPLUS_POR_CNID)
		goto found;

	label_len = be16_to_cpu(key->unicode_len) * 2;
	dbg("label unicode16 len %i", label_len);
	volume_id_set_label_raw(id, key->unicode, label_len);
	volume_id_set_label_unicode16(id, key->unicode, BE, label_len);

found:
	volume_id_set_usage(id, VOLUME_ID_FILESYSTEM);
	id->type = "hfsplus";

	return 0;
}
