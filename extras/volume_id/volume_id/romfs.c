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
#include "romfs.h"

struct romfs_super {
	__u8 magic[8];
	__u32 size;
	__u32 checksum;
	__u8 name[0];
} __attribute__((__packed__));

int volume_id_probe_romfs(struct volume_id *id, __u64 off)
{
	struct romfs_super *rfs;

	dbg("probing at offset %llu", off);

	rfs = (struct romfs_super *) volume_id_get_buffer(id, off, 0x200);
	if (rfs == NULL)
		return -1;

	if (memcmp(rfs->magic, "-rom1fs-", 4) == 0) {
		size_t len = strlen(rfs->name);

		if (len) {
			volume_id_set_label_raw(id, rfs->name, len);
			volume_id_set_label_string(id, rfs->name, len);
		}

		volume_id_set_usage(id, VOLUME_ID_FILESYSTEM);
		id->type = "romfs";
		return 0;
	}

	return -1;
}
