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

struct xfs_super_block {
	uint8_t	magic[4];
	uint32_t	blocksize;
	uint64_t	dblocks;
	uint64_t	rblocks;
	uint32_t	dummy1[2];
	uint8_t	uuid[16];
	uint32_t	dummy2[15];
	uint8_t	fname[12];
	uint32_t	dummy3[2];
	uint64_t	icount;
	uint64_t	ifree;
	uint64_t	fdblocks;
} PACKED;

int volume_id_probe_xfs(struct volume_id *id, uint64_t off, uint64_t size)
{
	struct xfs_super_block *xs;

	info("probing at offset 0x%llx", (unsigned long long) off);

	xs = (struct xfs_super_block *) volume_id_get_buffer(id, off, 0x200);
	if (xs == NULL)
		return -1;

	if (memcmp(xs->magic, "XFSB", 4) != 0)
		return -1;

	volume_id_set_label_raw(id, xs->fname, 12);
	volume_id_set_label_string(id, xs->fname, 12);
	volume_id_set_uuid(id, xs->uuid, UUID_DCE);

	volume_id_set_usage(id, VOLUME_ID_FILESYSTEM);
	id->type = "xfs";

	return 0;
}
