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
#include "ntfs.h"

struct ntfs_super_block {
	__u8	jump[3];
	__u8	oem_id[8];
	__u16	bytes_per_sector;
	__u8	sectors_per_cluster;
	__u16	reserved_sectors;
	__u8	fats;
	__u16	root_entries;
	__u16	sectors;
	__u8	media_type;
	__u16	sectors_per_fat;
	__u16	sectors_per_track;
	__u16	heads;
	__u32	hidden_sectors;
	__u32	large_sectors;
	__u16	unused[2];
	__u64	number_of_sectors;
	__u64	mft_cluster_location;
	__u64	mft_mirror_cluster_location;
	__s8	cluster_per_mft_record;
	__u8	reserved1[3];
	__s8	cluster_per_index_record;
	__u8	reserved2[3];
	__u8	volume_serial[8];
	__u16	checksum;
} __attribute__((__packed__)) *ns;

struct master_file_table_record {
	__u8	magic[4];
	__u16	usa_ofs;
	__u16	usa_count;
	__u64	lsn;
	__u16	sequence_number;
	__u16	link_count;
	__u16	attrs_offset;
	__u16	flags;
	__u32	bytes_in_use;
	__u32	bytes_allocated;
} __attribute__((__packed__)) *mftr;

struct file_attribute {
	__u32	type;
	__u32	len;
	__u8	non_resident;
	__u8	name_len;
	__u16	name_offset;
	__u16	flags;
	__u16	instance;
	__u32	value_len;
	__u16	value_offset;
} __attribute__((__packed__)) *attr;

struct volume_info {
	__u64 reserved;
	__u8 major_ver;
	__u8 minor_ver;
} __attribute__((__packed__)) *info;

#define MFT_RECORD_VOLUME			3
#define MFT_RECORD_ATTR_VOLUME_NAME		0x60
#define MFT_RECORD_ATTR_VOLUME_INFO		0x70
#define MFT_RECORD_ATTR_OBJECT_ID		0x40
#define MFT_RECORD_ATTR_END			0xffffffffu

int volume_id_probe_ntfs(struct volume_id *id, __u64 off)
{
	unsigned int sector_size;
	unsigned int cluster_size;
	__u64 mft_cluster;
	__u64 mft_off;
	unsigned int mft_record_size;
	unsigned int attr_type;
	unsigned int attr_off;
	unsigned int attr_len;
	unsigned int val_off;
	unsigned int val_len;
	const __u8 *buf;
	const __u8 *val;

	dbg("probing at offset 0x%llx", (unsigned long long) off);

	ns = (struct ntfs_super_block *) volume_id_get_buffer(id, off, 0x200);
	if (ns == NULL)
		return -1;

	if (memcmp(ns->oem_id, "NTFS", 4) != 0)
		return -1;

	volume_id_set_uuid(id, ns->volume_serial, UUID_NTFS);

	sector_size = le16_to_cpu(ns->bytes_per_sector);
	cluster_size = ns->sectors_per_cluster * sector_size;
	mft_cluster = le64_to_cpu(ns->mft_cluster_location);
	mft_off = mft_cluster * cluster_size;

	if (ns->cluster_per_mft_record < 0)
		/* size = -log2(mft_record_size); normally 1024 Bytes */
		mft_record_size = 1 << -ns->cluster_per_mft_record;
	else
		mft_record_size = ns->cluster_per_mft_record * cluster_size;

	dbg("sectorsize  0x%x", sector_size);
	dbg("clustersize 0x%x", cluster_size);
	dbg("mftcluster  %llu", (unsigned long long) mft_cluster);
	dbg("mftoffset  0x%llx", (unsigned long long) mft_off);
	dbg("cluster per mft_record  %i", ns->cluster_per_mft_record);
	dbg("mft record size  %i", mft_record_size);

	buf = volume_id_get_buffer(id, off + mft_off + (MFT_RECORD_VOLUME * mft_record_size),
			 mft_record_size);
	if (buf == NULL)
		goto found;

	mftr = (struct master_file_table_record*) buf;

	dbg("mftr->magic '%c%c%c%c'", mftr->magic[0], mftr->magic[1], mftr->magic[2], mftr->magic[3]);
	if (memcmp(mftr->magic, "FILE", 4) != 0)
		goto found;

	attr_off = le16_to_cpu(mftr->attrs_offset);
	dbg("file $Volume's attributes are at offset %i", attr_off);

	while (1) {
		attr = (struct file_attribute*) &buf[attr_off];
		attr_type = le32_to_cpu(attr->type);
		attr_len = le16_to_cpu(attr->len);
		val_off = le16_to_cpu(attr->value_offset);
		val_len = le32_to_cpu(attr->value_len);
		attr_off += attr_len;

		if (attr_len == 0)
			break;

		if (attr_off >= mft_record_size)
			break;

		if (attr_type == MFT_RECORD_ATTR_END)
			break;

		dbg("found attribute type 0x%x, len %i, at offset %i",
		    attr_type, attr_len, attr_off);

		if (attr_type == MFT_RECORD_ATTR_VOLUME_INFO) {
			dbg("found info, len %i", val_len);
			info = (struct volume_info*) (((__u8 *) attr) + val_off);
			snprintf(id->type_version, VOLUME_ID_FORMAT_SIZE-1,
				 "%u.%u", info->major_ver, info->minor_ver);
		}

		if (attr_type == MFT_RECORD_ATTR_VOLUME_NAME) {
			dbg("found label, len %i", val_len);
			if (val_len > VOLUME_ID_LABEL_SIZE)
				val_len = VOLUME_ID_LABEL_SIZE;

			val = ((__u8 *) attr) + val_off;
			volume_id_set_label_raw(id, val, val_len);
			volume_id_set_label_unicode16(id, val, LE, val_len);
		}
	}

found:
	volume_id_set_usage(id, VOLUME_ID_FILESYSTEM);
	id->type = "ntfs";

	return 0;
}
