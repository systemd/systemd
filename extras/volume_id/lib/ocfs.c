/*
 * volume_id - reads filesystem label and uuid
 *
 * Copyright (C) 2004 Andre Masella <andre@masella.no-ip.org>
 * Copyright (C) 2005 Kay Sievers <kay.sievers@vrfy.org>
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


struct ocfs1_super_block_header {
	uint32_t	minor_version;
	uint32_t	major_version;
	uint8_t		signature[128];
	uint8_t		mount_point[128];
	uint64_t	serial_num;
	uint64_t	device_size;
	uint64_t	start_off;
	uint64_t	bitmap_off;
	uint64_t	publ_off;
	uint64_t	vote_off;
	uint64_t	root_bitmap_off;
	uint64_t	data_start_off;
	uint64_t	root_bitmap_size;
	uint64_t	root_off;
	uint64_t	root_size;
	uint64_t	cluster_size;
	uint64_t	num_nodes;
	uint64_t	num_clusters;
	uint64_t	dir_node_size;
	uint64_t	file_node_size;
	uint64_t	internal_off;
	uint64_t	node_cfg_off;
	uint64_t	node_cfg_size;
	uint64_t	new_cfg_off;
	uint32_t	prot_bits;
	int32_t		excl_mount;
} PACKED;

struct ocfs1_super_block_label {
	struct ocfs1_disk_lock {
		uint32_t	curr_master;
		uint8_t		file_lock;
		uint8_t		compat_pad[3];
		uint64_t	last_write_time;
		uint64_t	last_read_time;
		uint32_t	writer_node_num;
		uint32_t	reader_node_num;
		uint64_t	oin_node_map;
		uint64_t	dlock_seq_num;
	} PACKED disk_lock;
	uint8_t		label[64];
	uint16_t	label_len;
	uint8_t		vol_id[16];
	uint16_t	vol_id_len;
	uint8_t		cluster_name[64];
	uint16_t	cluster_name_len;
} PACKED;

struct ocfs2_super_block {
	uint8_t		i_signature[8];
	uint32_t	i_generation;
	int16_t		i_suballoc_slot;
	uint16_t	i_suballoc_bit;
	uint32_t	i_reserved0;
	uint32_t	i_clusters;
	uint32_t	i_uid;
	uint32_t	i_gid;
	uint64_t	i_size;
	uint16_t	i_mode;
	uint16_t	i_links_count;
	uint32_t	i_flags;
	uint64_t	i_atime;
	uint64_t	i_ctime;
	uint64_t	i_mtime;
	uint64_t	i_dtime;
	uint64_t	i_blkno;
	uint64_t	i_last_eb_blk;
	uint32_t	i_fs_generation;
	uint32_t	i_atime_nsec;
	uint32_t	i_ctime_nsec;
	uint32_t	i_mtime_nsec;
	uint64_t	i_reserved1[9];
	uint64_t	i_pad1;
	uint16_t	s_major_rev_level;
	uint16_t	s_minor_rev_level;
	uint16_t	s_mnt_count;
	int16_t		s_max_mnt_count;
	uint16_t	s_state;
	uint16_t	s_errors;
	uint32_t	s_checkinterval;
	uint64_t	s_lastcheck;
	uint32_t	s_creator_os;
	uint32_t	s_feature_compat;
	uint32_t	s_feature_incompat;
	uint32_t	s_feature_ro_compat;
	uint64_t	s_root_blkno;
	uint64_t	s_system_dir_blkno;
	uint32_t	s_blocksize_bits;
	uint32_t	s_clustersize_bits;
	uint16_t	s_max_slots;
	uint16_t	s_reserved1;
	uint32_t	s_reserved2;
	uint64_t	s_first_cluster_group;
	uint8_t		s_label[64];
	uint8_t		s_uuid[16];
} PACKED;

int volume_id_probe_ocfs1(struct volume_id *id, uint64_t off, uint64_t size)
{
	const uint8_t *buf;
	struct ocfs1_super_block_header *osh;
	struct ocfs1_super_block_label *osl;

	info("probing at offset 0x%llx", (unsigned long long) off);

	buf = volume_id_get_buffer(id, off, 0x200);
	if (buf == NULL)
		return -1;

	osh = (struct ocfs1_super_block_header *) buf;
	if (memcmp(osh->signature, "OracleCFS", 9) != 0)
		return -1;
	snprintf(id->type_version, sizeof(id->type_version)-1,
		 "%u.%u", osh->major_version, osh->minor_version);

	dbg("found OracleCFS signature, now reading label");
	buf = volume_id_get_buffer(id, off + 0x200, 0x200);
	if (buf == NULL)
		return -1;

	osl = (struct ocfs1_super_block_label *) buf;
	volume_id_set_usage(id, VOLUME_ID_FILESYSTEM);
	if (osl->label_len <= 64) {
		volume_id_set_label_raw(id, osl->label, 64);
		volume_id_set_label_string(id, osl->label, 64);
	}
	if (osl->vol_id_len == 16)
		volume_id_set_uuid(id, osl->vol_id, UUID_DCE);
	id->type = "ocfs";
	return 0;
}

#define OCFS2_MAX_BLOCKSIZE		0x1000
#define OCFS2_SUPER_BLOCK_BLKNO		2

int volume_id_probe_ocfs2(struct volume_id *id, uint64_t off, uint64_t size)
{
	const uint8_t *buf;
	struct ocfs2_super_block *os;
	size_t blksize;

	info("probing at offset 0x%llx", (unsigned long long) off);

	for (blksize = 0x200; blksize <= OCFS2_MAX_BLOCKSIZE; blksize <<= 1) {
		buf = volume_id_get_buffer(id, off + OCFS2_SUPER_BLOCK_BLKNO * blksize, 0x200);
		if (buf == NULL)
			return -1;

		os = (struct ocfs2_super_block *) buf;
		if (memcmp(os->i_signature, "OCFSV2", 6) != 0)
			continue;

		volume_id_set_usage(id, VOLUME_ID_FILESYSTEM);
		volume_id_set_label_raw(id, os->s_label, 64);
		volume_id_set_label_string(id, os->s_label, 64);
		volume_id_set_uuid(id, os->s_uuid, UUID_DCE);
		snprintf(id->type_version, sizeof(id->type_version)-1,
			 "%u.%u", os->s_major_rev_level, os->s_minor_rev_level);
		id->type = "ocfs2";
		return 0;
	}
	return -1;
}
