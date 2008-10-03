/*
 * volume_id - reads filesystem label and uuid
 *
 * Copyright (C) 2008 Kay Sievers <kay.sievers@vrfy.org>
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
#include <byteswap.h>

#include "libvolume_id.h"
#include "libvolume_id-private.h"

struct btrfs_super_block {
	uint8_t csum[32];
	uint8_t fsid[16];
	uint64_t bytenr;
	uint64_t flags;
	uint8_t magic[8];
	uint64_t generation;
	uint64_t root;
	uint64_t chunk_root;
	uint64_t log_root;
	uint64_t total_bytes;
	uint64_t bytes_used;
	uint64_t root_dir_objectid;
	uint64_t num_devices;
	uint32_t sectorsize;
	uint32_t nodesize;
	uint32_t leafsize;
	uint32_t stripesize;
	uint32_t sys_chunk_array_size;
	uint8_t root_level;
	uint8_t chunk_root_level;
	uint8_t log_root_level;
	struct btrfs_dev_item {
		uint64_t devid;
		uint64_t total_bytes;
		uint64_t bytes_used;
		uint32_t io_align;
		uint32_t io_width;
		uint32_t sector_size;
		uint64_t type;
		uint32_t dev_group;
		uint8_t seek_speed;
		uint8_t bandwidth;
		uint8_t uuid[16];
	} PACKED dev_item;
	uint8_t label[256];
} PACKED;

int volume_id_probe_btrfs(struct volume_id *id, uint64_t off, uint64_t size)
{
	const uint8_t *buf;
	struct btrfs_super_block *bfs;

	info("probing at offset 0x%" PRIx64 ", size 0x%" PRIx64 "\n", off, size);

	buf = volume_id_get_buffer(id, off + 0x4000, 0x200);
	if (buf == NULL)
		return -1;
	bfs = (struct btrfs_super_block *)buf;
	if (memcmp(bfs->magic, "_B9RfS_M", 8) != 0)
		return -1;
	volume_id_set_uuid(id, bfs->fsid, 0, UUID_DCE);
	volume_id_set_label_raw(id, bfs->label, 256);
	volume_id_set_label_string(id, bfs->label, 256);
	volume_id_set_usage(id, VOLUME_ID_FILESYSTEM);
	id->type = "btrfs";
	return 0;
}
