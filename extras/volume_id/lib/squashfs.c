/*
 * volume_id - reads filesystem label and uuid
 *
 * Copyright (C) 2006 Kay Sievers <kay.sievers@vrfy.org>
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

#define SQUASHFS_MAGIC		0x73717368

struct squashfs_super {
	uint32_t		s_magic;
} PACKED;

int volume_id_probe_squashfs(struct volume_id *id, uint64_t off, uint64_t size)
{
	struct squashfs_super *sqs;

	info("probing at offset 0x%llx", (unsigned long long) off);

	sqs = (struct squashfs_super *) volume_id_get_buffer(id, off + 0x200, 0x200);
	if (sqs == NULL)
		return -1;

	if (sqs->s_magic == SQUASHFS_MAGIC || sqs->s_magic == bswap_32(SQUASHFS_MAGIC)) {
		volume_id_set_usage(id, VOLUME_ID_FILESYSTEM);
		id->type = "squashfs";
		return 0;
	}

	return -1;
}
