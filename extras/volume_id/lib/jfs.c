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

struct jfs_super_block {
	uint8_t		magic[4];
	uint32_t	version;
	uint64_t	size;
	uint32_t	bsize;
	uint32_t	dummy1;
	uint32_t	pbsize;
	uint32_t	dummy2[27];
	uint8_t		uuid[16];
	uint8_t		label[16];
	uint8_t		loguuid[16];
} PACKED;

#define JFS_SUPERBLOCK_OFFSET			0x8000

int volume_id_probe_jfs(struct volume_id *id, uint64_t off, uint64_t size)
{
	struct jfs_super_block *js;

	info("probing at offset 0x%llx", (unsigned long long) off);

	js = (struct jfs_super_block *) volume_id_get_buffer(id, off + JFS_SUPERBLOCK_OFFSET, 0x200);
	if (js == NULL)
		return -1;

	if (memcmp(js->magic, "JFS1", 4) != 0)
		return -1;

	volume_id_set_label_raw(id, js->label, 16);
	volume_id_set_label_string(id, js->label, 16);
	volume_id_set_uuid(id, js->uuid, UUID_DCE);

	volume_id_set_usage(id, VOLUME_ID_FILESYSTEM);
	id->type = "jfs";

	return 0;
}
