/*
 * volume_id - reads filesystem label and uuid
 *
 * Copyright (C) 2005 Kay Sievers <kay.sievers@vrfy.org>
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

struct minix_super_block
{
	uint16_t	s_ninodes;
	uint16_t	s_nzones;
	uint16_t	s_imap_blocks;
	uint16_t	s_zmap_blocks;
	uint16_t	s_firstdatazone;
	uint16_t	s_log_zone_size;
	uint32_t	s_max_size;
	uint16_t	s_magic;
	uint16_t	s_state;
	uint32_t	s_zones;
} PACKED;

#define MINIX_SUPERBLOCK_OFFSET			0x400

int volume_id_probe_minix(struct volume_id *id, uint64_t off, uint64_t size)
{
	struct minix_super_block *ms;

	info("probing at offset 0x%llx", (unsigned long long) off);

	ms = (struct minix_super_block *) volume_id_get_buffer(id, off + MINIX_SUPERBLOCK_OFFSET, 0x200);
	if (ms == NULL)
		return -1;

	if (le16_to_cpu(ms->s_magic) == 0x137f) {
		strcpy(id->type_version, "1");
		goto found;
	}

	if (le16_to_cpu(ms->s_magic) == 0x1387) {
		strcpy(id->type_version, "1");
		goto found;
	}

	if (le16_to_cpu(ms->s_magic) == 0x2468) {
		strcpy(id->type_version, "2");
		goto found;
	}

	if (le16_to_cpu(ms->s_magic) == 0x2478) {
		strcpy(id->type_version, "2");
		goto found;
	}

	goto exit;

found:
	volume_id_set_usage(id, VOLUME_ID_FILESYSTEM);
	id->type = "minix";
	return 0;

exit:
	return -1;
}
