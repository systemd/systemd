/*
 * volume_id - reads filesystem label and uuid
 *
 * Copyright (C) 2005 Kay Sievers <kay.sievers@vrfy.org>
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

struct hpfs_boot_block
{
	uint8_t		jmp[3];
	uint8_t		oem_id[8];
	uint8_t		bytes_per_sector[2];
	uint8_t		sectors_per_cluster;
	uint8_t		n_reserved_sectors[2];
	uint8_t		n_fats;
	uint8_t		n_rootdir_entries[2];
	uint8_t		n_sectors_s[2];
	uint8_t		media_byte;
	uint16_t	sectors_per_fat;
	uint16_t	sectors_per_track;
	uint16_t	heads_per_cyl;
	uint32_t	n_hidden_sectors;
	uint32_t	n_sectors_l;
	uint8_t		drive_number;
	uint8_t		mbz;
	uint8_t		sig_28h;
	uint8_t		vol_serno[4];
	uint8_t		vol_label[11];
	uint8_t		sig_hpfs[8];
	uint8_t		pad[448];
	uint8_t		magic[2];
} PACKED;

struct hpfs_super
{
	uint8_t		magic[4];
	uint8_t		magic1[4];
	uint8_t		version;
} PACKED;


struct hpfs_spare_super
{
	uint8_t		magic[4];
	uint8_t		magic1[4];
} PACKED;

#define HPFS_SUPERBLOCK_OFFSET			0x2000
#define HPFS_SUPERBLOCK_SPARE_OFFSET		0x2200

int volume_id_probe_hpfs(struct volume_id *id, uint64_t off, uint64_t size)
{
	struct hpfs_super *hs;
	struct hpfs_spare_super *hss;
	struct hpfs_boot_block *hbb;

	info("probing at offset 0x%llx\n", (unsigned long long) off);

	hs = (struct hpfs_super *) volume_id_get_buffer(id, off + HPFS_SUPERBLOCK_OFFSET, 0x400);
	if (hs == NULL)
		return -1;
	if (memcmp(hs->magic, "\x49\xe8\x95\xf9", 4) != 0)
		return -1;

	hss = (struct hpfs_spare_super *) volume_id_get_buffer(id, off + HPFS_SUPERBLOCK_SPARE_OFFSET, 0x200);
	if (hss == NULL)
		return -1;
	if (memcmp(hss->magic, "\x49\x18\x91\xf9", 4) != 0)
		return -1;

	sprintf(id->type_version, "%u", hs->version);
	volume_id_set_usage(id, VOLUME_ID_FILESYSTEM);
	id->type = "hpfs";

	/* if boot block looks valid, read label and uuid from there */
	hbb = (struct hpfs_boot_block *) volume_id_get_buffer(id, off, 0x200);
	if (hs == NULL)
		return -1;
	if (memcmp(hbb->magic, "\x55\xaa", 2) == 0 &&
	    memcmp(hbb->sig_hpfs, "HPFS", 4) == 0 &&
	    hbb->sig_28h == 0x28) {
		volume_id_set_label_raw(id, hbb->vol_label, 11);
		volume_id_set_label_string(id, hbb->vol_label, 11);
		volume_id_set_uuid(id, hbb->vol_serno, 0, UUID_DOS);
	}

	return 0;
}
