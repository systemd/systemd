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

struct romfs_super {
	uint8_t magic[8];
	uint32_t size;
	uint32_t checksum;
	uint8_t name[0];
} PACKED;

int volume_id_probe_romfs(struct volume_id *id, uint64_t off, uint64_t size)
{
	struct romfs_super *rfs;

	info("probing at offset 0x%llx", (unsigned long long) off);

	rfs = (struct romfs_super *) volume_id_get_buffer(id, off, 0x200);
	if (rfs == NULL)
		return -1;

	if (memcmp(rfs->magic, "-rom1fs-", 4) == 0) {
		size_t len = strlen((char *)rfs->name);

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
