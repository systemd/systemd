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
#include "fat.h"

#define FAT12_MAX			0xff5
#define FAT16_MAX			0xfff5
#define FAT_ATTR_VOLUME_ID		0x08
#define FAT_ATTR_DIR			0x10
#define FAT_ATTR_LONG_NAME		0x0f
#define FAT_ATTR_MASK			0x3f
#define FAT_ENTRY_FREE			0xe5

struct vfat_super_block {
	__u8	boot_jump[3];
	__u8	sysid[8];
	__u16	sector_size;
	__u8	sectors_per_cluster;
	__u16	reserved;
	__u8	fats;
	__u16	dir_entries;
	__u16	sectors;
	__u8	media;
	__u16	fat_length;
	__u16	secs_track;
	__u16	heads;
	__u32	hidden;
	__u32	total_sect;
	union {
		struct fat_super_block {
			__u8	unknown[3];
			__u8	serno[4];
			__u8	label[11];
			__u8	magic[8];
			__u8	dummy2[192];
			__u8	pmagic[2];
		} __attribute__((__packed__)) fat;
		struct fat32_super_block {
			__u32	fat32_length;
			__u16	flags;
			__u8	version[2];
			__u32	root_cluster;
			__u16	insfo_sector;
			__u16	backup_boot;
			__u16	reserved2[6];
			__u8	unknown[3];
			__u8	serno[4];
			__u8	label[11];
			__u8	magic[8];
			__u8	dummy2[164];
			__u8	pmagic[2];
		} __attribute__((__packed__)) fat32;
	} __attribute__((__packed__)) type;
} __attribute__((__packed__));

struct vfat_dir_entry {
	__u8	name[11];
	__u8	attr;
	__u16	time_creat;
	__u16	date_creat;
	__u16	time_acc;
	__u16	date_acc;
	__u16	cluster_high;
	__u16	time_write;
	__u16	date_write;
	__u16	cluster_low;
	__u32	size;
} __attribute__((__packed__));

static char *get_attr_volume_id(struct vfat_dir_entry *dir, unsigned int count)
{
	unsigned int i;

	for (i = 0; i < count; i++) {
		/* end marker */
		if (dir[i].name[0] == 0x00) {
			dbg("end of dir");
			break;
		}

		/* empty entry */
		if (dir[i].name[0] == FAT_ENTRY_FREE)
			continue;

		/* long name */
		if ((dir[i].attr & FAT_ATTR_MASK) == FAT_ATTR_LONG_NAME)
			continue;

		if ((dir[i].attr & (FAT_ATTR_VOLUME_ID | FAT_ATTR_DIR)) == FAT_ATTR_VOLUME_ID) {
			/* labels do not have file data */
			if (dir[i].cluster_high != 0 || dir[i].cluster_low != 0)
				continue;

			dbg("found ATTR_VOLUME_ID id in root dir");
			return dir[i].name;
		}

		dbg("skip dir entry");
	}

	return NULL;
}

int volume_id_probe_vfat(struct volume_id *id, __u64 off)
{
	struct vfat_super_block *vs;
	struct vfat_dir_entry *dir;
	__u16 sector_size;
	__u16 dir_entries;
	__u32 sect_count;
	__u16 reserved;
	__u32 fat_size;
	__u32 root_cluster;
	__u32 dir_size;
	__u32 cluster_count;
	__u32 fat_length;
	__u64 root_start;
	__u32 start_data_sect;
	__u16 root_dir_entries;
	__u8 *buf;
	__u32 buf_size;
	__u8 *label = NULL;
	__u32 next;
	int maxloop;

	dbg("probing at offset %llu", off);

	vs = (struct vfat_super_block *) volume_id_get_buffer(id, off, 0x200);
	if (vs == NULL)
		return -1;

	/* believe only that's fat, don't trust the version
	 * the cluster_count will tell us
	 */
	if (memcmp(vs->sysid, "NTFS", 4) == 0)
		return -1;

	if (memcmp(vs->type.fat32.magic, "MSWIN", 5) == 0)
		goto valid;

	if (memcmp(vs->type.fat32.magic, "FAT32   ", 8) == 0)
		goto valid;

	if (memcmp(vs->type.fat.magic, "FAT16   ", 8) == 0)
		goto valid;

	if (memcmp(vs->type.fat.magic, "MSDOS", 5) == 0)
		goto valid;

	if (memcmp(vs->type.fat.magic, "FAT12   ", 8) == 0)
		goto valid;

	/*
	 * There are old floppies out there without a magic, so we check
	 * for well known values and guess if it's a fat volume
	 */

	/* boot jump address check */
	if ((vs->boot_jump[0] != 0xeb || vs->boot_jump[2] != 0x90) &&
	     vs->boot_jump[0] != 0xe9)
		return -1;

	/* heads check */
	if (vs->heads == 0)
		return -1;

	/* cluster size check*/	
	if (vs->sectors_per_cluster == 0 ||
	    (vs->sectors_per_cluster & (vs->sectors_per_cluster-1)))
		return -1;

	/* media check */
	if (vs->media < 0xf8 && vs->media != 0xf0)
		return -1;

	/* fat count*/
	if (vs->fats != 2)
		return -1;

valid:
	/* sector size check */
	sector_size = le16_to_cpu(vs->sector_size);
	if (sector_size != 0x200 && sector_size != 0x400 &&
	    sector_size != 0x800 && sector_size != 0x1000)
		return -1;

	dbg("sector_size 0x%x", sector_size);
	dbg("sectors_per_cluster 0x%x", vs->sectors_per_cluster);

	dir_entries = le16_to_cpu(vs->dir_entries);
	reserved = le16_to_cpu(vs->reserved);
	dbg("reserved 0x%x", reserved);

	sect_count = le16_to_cpu(vs->sectors);
	if (sect_count == 0)
		sect_count = le32_to_cpu(vs->total_sect);
	dbg("sect_count 0x%x", sect_count);

	fat_length = le16_to_cpu(vs->fat_length);
	if (fat_length == 0)
		fat_length = le32_to_cpu(vs->type.fat32.fat32_length);
	dbg("fat_length 0x%x", fat_length);

	fat_size = fat_length * vs->fats;
	dir_size = ((dir_entries * sizeof(struct vfat_dir_entry)) +
			(sector_size-1)) / sector_size;
	dbg("dir_size 0x%x", dir_size);

	cluster_count = sect_count - (reserved + fat_size + dir_size);
	cluster_count /= vs->sectors_per_cluster;
	dbg("cluster_count 0x%x", cluster_count);

	if (cluster_count < FAT12_MAX) {
		strcpy(id->type_version, "FAT12");
	} else if (cluster_count < FAT16_MAX) {
		strcpy(id->type_version, "FAT16");
	} else {
		strcpy(id->type_version, "FAT32");
		goto fat32;
	}

	/* the label may be an attribute in the root directory */
	root_start = (reserved + fat_size) * sector_size;
	dbg("root dir start 0x%llx", root_start);
	root_dir_entries = le16_to_cpu(vs->dir_entries);
	dbg("expected entries 0x%x", root_dir_entries);

	buf_size = root_dir_entries * sizeof(struct vfat_dir_entry);
	buf = volume_id_get_buffer(id, off + root_start, buf_size);
	if (buf == NULL)
		goto found;

	dir = (struct vfat_dir_entry*) buf;

	label = get_attr_volume_id(dir, root_dir_entries);

	vs = (struct vfat_super_block *) volume_id_get_buffer(id, off, 0x200);
	if (vs == NULL)
		return -1;

	if (label != NULL && memcmp(label, "NO NAME    ", 11) != 0) {
		volume_id_set_label_raw(id, label, 11);
		volume_id_set_label_string(id, label, 11);
	} else if (memcmp(vs->type.fat.label, "NO NAME    ", 11) != 0) {
		volume_id_set_label_raw(id, vs->type.fat.label, 11);
		volume_id_set_label_string(id, vs->type.fat.label, 11);
	}
	volume_id_set_uuid(id, vs->type.fat.serno, UUID_DOS);
	goto found;

fat32:
	/* FAT32 root dir is a cluster chain like any other directory */
	buf_size = vs->sectors_per_cluster * sector_size;
	root_cluster = le32_to_cpu(vs->type.fat32.root_cluster);
	dbg("root dir cluster %u", root_cluster);
	start_data_sect = reserved + fat_size;

	next = root_cluster;
	maxloop = 100;
	while (--maxloop) {
		__u32 next_sect_off;
		__u64 next_off;
		__u64 fat_entry_off;
		int count;

		dbg("next cluster %u", next);
		next_sect_off = (next - 2) * vs->sectors_per_cluster;
		next_off = (start_data_sect + next_sect_off) * sector_size;
		dbg("cluster offset 0x%llx", next_off);

		/* get cluster */
		buf = volume_id_get_buffer(id, off + next_off, buf_size);
		if (buf == NULL)
			goto found;

		dir = (struct vfat_dir_entry*) buf;
		count = buf_size / sizeof(struct vfat_dir_entry);
		dbg("expected entries 0x%x", count);

		label = get_attr_volume_id(dir, count);
		if (label)
			break;

		/* get FAT entry */
		fat_entry_off = (reserved * sector_size) + (next * sizeof(__u32));
		buf = volume_id_get_buffer(id, off + fat_entry_off, buf_size);
		if (buf == NULL)
			goto found;

		/* set next cluster */
		next = le32_to_cpu(*((__u32 *) buf) & 0x0fffffff);
		if (next == 0)
			break;
	}
	if (maxloop == 0)
		dbg("reached maximum follow count of root cluster chain, give up");

	vs = (struct vfat_super_block *) volume_id_get_buffer(id, off, 0x200);
	if (vs == NULL)
		return -1;

	if (label != NULL && memcmp(label, "NO NAME    ", 11) != 0) {
		volume_id_set_label_raw(id, label, 11);
		volume_id_set_label_string(id, label, 11);
	} else if (memcmp(vs->type.fat32.label, "NO NAME    ", 11) != 0) {
		volume_id_set_label_raw(id, vs->type.fat32.label, 11);
		volume_id_set_label_string(id, vs->type.fat32.label, 11);
	}
	volume_id_set_uuid(id, vs->type.fat32.serno, UUID_DOS);

found:
	volume_id_set_usage(id, VOLUME_ID_FILESYSTEM);
	id->type = "vfat";

	return 0;
}
