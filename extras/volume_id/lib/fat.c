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

#define FAT12_MAX			0xff5
#define FAT16_MAX			0xfff5
#define FAT_ATTR_VOLUME_ID		0x08
#define FAT_ATTR_DIR			0x10
#define FAT_ATTR_LONG_NAME		0x0f
#define FAT_ATTR_MASK			0x3f
#define FAT_ENTRY_FREE			0xe5

struct vfat_super_block {
	uint8_t		boot_jump[3];
	uint8_t		sysid[8];
	uint16_t	sector_size;
	uint8_t		sectors_per_cluster;
	uint16_t	reserved;
	uint8_t		fats;
	uint16_t	dir_entries;
	uint16_t	sectors;
	uint8_t		media;
	uint16_t	fat_length;
	uint16_t	secs_track;
	uint16_t	heads;
	uint32_t	hidden;
	uint32_t	total_sect;
	union {
		struct fat_super_block {
			uint8_t		unknown[3];
			uint8_t		serno[4];
			uint8_t		label[11];
			uint8_t		magic[8];
			uint8_t		dummy2[192];
			uint8_t		pmagic[2];
		} PACKED fat;
		struct fat32_super_block {
			uint32_t	fat32_length;
			uint16_t	flags;
			uint8_t		version[2];
			uint32_t	root_cluster;
			uint16_t	fsinfo_sector;
			uint16_t	backup_boot;
			uint16_t	reserved2[6];
			uint8_t		unknown[3];
			uint8_t		serno[4];
			uint8_t		label[11];
			uint8_t		magic[8];
			uint8_t		dummy2[164];
			uint8_t		pmagic[2];
		} PACKED fat32;
	} PACKED type;
} PACKED;

struct fat32_fsinfo {
	uint8_t signature1[4];
	uint32_t reserved1[120];
	uint8_t signature2[4];
	uint32_t free_clusters;
	uint32_t next_cluster;
	uint32_t reserved2[4];
} PACKED;

struct vfat_dir_entry {
	uint8_t		name[11];
	uint8_t		attr;
	uint16_t	time_creat;
	uint16_t	date_creat;
	uint16_t	time_acc;
	uint16_t	date_acc;
	uint16_t	cluster_high;
	uint16_t	time_write;
	uint16_t	date_write;
	uint16_t	cluster_low;
	uint32_t	size;
} PACKED;

static uint8_t *get_attr_volume_id(struct vfat_dir_entry *dir, unsigned int count)
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

int volume_id_probe_vfat(struct volume_id *id, uint64_t off, uint64_t size)
{
	struct vfat_super_block *vs;
	struct vfat_dir_entry *dir;
	struct fat32_fsinfo *fsinfo;
	uint16_t sector_size;
	uint16_t dir_entries;
	uint32_t sect_count;
	uint16_t reserved;
	uint32_t fat_size;
	uint32_t root_cluster;
	uint32_t dir_size;
	uint32_t cluster_count;
	uint16_t fat_length;
	uint32_t fat32_length;
	uint64_t root_start;
	uint32_t start_data_sect;
	uint16_t root_dir_entries;
	uint16_t fsinfo_sect;
	uint8_t *buf;
	uint32_t buf_size;
	uint8_t *label = NULL;
	uint32_t next;
	int maxloop;

	info("probing at offset 0x%llx", (unsigned long long) off);

	buf = volume_id_get_buffer(id, off, 0x400);
	if (buf == NULL)
		return -1;

	/* check signature */
	if (buf[510] != 0x55 || buf[511] != 0xaa)
		return -1;

	vs = (struct vfat_super_block *) buf;
	if (memcmp(vs->sysid, "NTFS", 4) == 0)
		return -1;

	/* believe only that's fat, don't trust the version */
	if (memcmp(vs->type.fat32.magic, "MSWIN", 5) == 0)
		goto magic;

	if (memcmp(vs->type.fat32.magic, "FAT32   ", 8) == 0)
		goto magic;

	if (memcmp(vs->type.fat.magic, "FAT16   ", 8) == 0)
		goto magic;

	if (memcmp(vs->type.fat.magic, "MSDOS", 5) == 0)
		goto magic;

	if (memcmp(vs->type.fat.magic, "FAT12   ", 8) == 0)
		goto magic;

	/* some old floppies don't have a magic, expect the boot jump address to match */
	if ((vs->boot_jump[0] != 0xeb || vs->boot_jump[2] != 0x90) &&
	     vs->boot_jump[0] != 0xe9)
		return -1;

magic:
	/* reserverd sector count */
	if (!vs->reserved)
		return -1;

	/* fat count*/
	if (!vs->fats)
		return -1;

	/* media check */
	if (vs->media < 0xf8 && vs->media != 0xf0)
		return -1;

	/* cluster size check*/	
	if (vs->sectors_per_cluster == 0 ||
	    (vs->sectors_per_cluster & (vs->sectors_per_cluster-1)))
		return -1;

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
	dbg("fat_length 0x%x", fat_length);
	fat32_length = le32_to_cpu(vs->type.fat32.fat32_length);
	dbg("fat32_length 0x%x", fat32_length);

	if (fat_length)
		fat_size = fat_length * vs->fats;
	else if (fat32_length)
		fat_size = fat32_length * vs->fats;
	else
		return -1;
	dbg("fat_size 0x%x", fat_size);

	dir_size = ((dir_entries * sizeof(struct vfat_dir_entry)) +
			(sector_size-1)) / sector_size;
	dbg("dir_size 0x%x", dir_size);

	cluster_count = sect_count - (reserved + fat_size + dir_size);
	cluster_count /= vs->sectors_per_cluster;
	dbg("cluster_count 0x%x", cluster_count);

	/* must be FAT32 */
	if (!fat_length && fat32_length)
		goto fat32;

	/* cluster_count tells us the format */
	if (cluster_count < FAT12_MAX)
		strcpy(id->type_version, "FAT12");
	else if (cluster_count < FAT16_MAX)
		strcpy(id->type_version, "FAT16");
	else
		goto fat32;

	/* the label may be an attribute in the root directory */
	root_start = (reserved + fat_size) * sector_size;
	dbg("root dir start 0x%llx", (unsigned long long) root_start);
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
	/* FAT32 should have a valid signature in the fsinfo block */
	fsinfo_sect = le16_to_cpu(vs->type.fat32.fsinfo_sector);
	buf = volume_id_get_buffer(id, off + (fsinfo_sect * sector_size), 0x200);
	if (buf == NULL)
		return -1;
	fsinfo = (struct fat32_fsinfo *) buf;
	if (memcmp(fsinfo->signature1, "\x52\x52\x61\x41", 4) != 0)
		return -1;
	if (memcmp(fsinfo->signature2, "\x72\x72\x41\x61", 4) != 0)
		return -1 ;

	vs = (struct vfat_super_block *) volume_id_get_buffer(id, off, 0x200);
	if (vs == NULL)
		return -1;

	strcpy(id->type_version, "FAT32");

	/* FAT32 root dir is a cluster chain like any other directory */
	buf_size = vs->sectors_per_cluster * sector_size;
	root_cluster = le32_to_cpu(vs->type.fat32.root_cluster);
	dbg("root dir cluster %u", root_cluster);
	start_data_sect = reserved + fat_size;

	next = root_cluster;
	maxloop = 100;
	while (--maxloop) {
		uint32_t next_sect_off;
		uint64_t next_off;
		uint64_t fat_entry_off;
		int count;

		dbg("next cluster %u", next);
		next_sect_off = (next - 2) * vs->sectors_per_cluster;
		next_off = (start_data_sect + next_sect_off) * sector_size;
		dbg("cluster offset 0x%llx", (unsigned long long) next_off);

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
		fat_entry_off = (reserved * sector_size) + (next * sizeof(uint32_t));
		buf = volume_id_get_buffer(id, off + fat_entry_off, buf_size);
		if (buf == NULL)
			goto found;

		/* set next cluster */
		next = le32_to_cpu(*((uint32_t *) buf)) & 0x0fffffff;
		if (next < 2 || next >= 0x0ffffff0)
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
