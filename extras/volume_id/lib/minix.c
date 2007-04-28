/*
 * volume_id - reads filesystem label and uuid
 *
 * Copyright (C) 2005-2007 Kay Sievers <kay.sievers@vrfy.org>
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

#define MINIX_SUPERBLOCK_OFFSET			0x400

#define MINIX_SUPER_MAGIC			0x137F
#define MINIX_SUPER_MAGIC2			0x138F
#define MINIX2_SUPER_MAGIC			0x2468
#define MINIX2_SUPER_MAGIC2			0x2478
#define MINIX3_SUPER_MAGIC			0x4d5a

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

struct minix3_super_block {
	uint32_t	s_ninodes;
	uint16_t	s_pad0;
	uint16_t	s_imap_blocks;
	uint16_t	s_zmap_blocks;
	uint16_t	s_firstdatazone;
	uint16_t	s_log_zone_size;
	uint16_t	s_pad1;
	uint32_t	s_max_size;
	uint32_t	s_zones;
	uint16_t	s_magic;
	uint16_t	s_pad2;
	uint16_t	s_blocksize;
	uint8_t 	s_disk_version;
} PACKED;

int volume_id_probe_minix(struct volume_id *id, uint64_t off, uint64_t size)
{
	uint8_t *buf;
	struct minix_super_block *ms;
	struct minix3_super_block *m3s;

	info("probing at offset 0x%llx", (unsigned long long) off);

	buf = volume_id_get_buffer(id, off + MINIX_SUPERBLOCK_OFFSET, 0x200);
	if (buf == NULL)
		return -1;

	ms = (struct minix_super_block *) buf;

	if (ms->s_magic == MINIX_SUPER_MAGIC ||
	    ms->s_magic == bswap_16(MINIX_SUPER_MAGIC)) {
		strcpy(id->type_version, "1");
		goto found;
	}
	if (ms->s_magic == MINIX_SUPER_MAGIC2 ||
	    ms->s_magic == bswap_16(MINIX_SUPER_MAGIC2)) {
		strcpy(id->type_version, "1");
		goto found;
	}
	if (ms->s_magic == MINIX2_SUPER_MAGIC ||
	    ms->s_magic == bswap_16(MINIX2_SUPER_MAGIC)) {
		strcpy(id->type_version, "2");
		goto found;
	}
	if (ms->s_magic == MINIX2_SUPER_MAGIC2 ||
	    ms->s_magic == bswap_16(MINIX2_SUPER_MAGIC2)) {
		strcpy(id->type_version, "2");
		goto found;
	}

	m3s = (struct minix3_super_block *) buf;
	if (m3s->s_magic == MINIX3_SUPER_MAGIC ||
	    m3s->s_magic == bswap_16(MINIX3_SUPER_MAGIC)) {
		strcpy(id->type_version, "3");
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
