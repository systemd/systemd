/*
 * volume_id - reads filesystem label and uuid
 *
 * Copyright (C) 2005 Kay Sievers <kay.sievers@vrfy.org>
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
#include "minix.h"

struct minix_super_block
{
	__u16	s_ninodes;
	__u16	s_nzones;
	__u16	s_imap_blocks;
	__u16	s_zmap_blocks;
	__u16	s_firstdatazone;
	__u16	s_log_zone_size;
	__u32	s_max_size;
	__u16	s_magic;
	__u16	s_state;
	__u32	s_zones;
} __attribute__((__packed__));

#define MINIX_SUPERBLOCK_OFFSET			0x400

int volume_id_probe_minix(struct volume_id *id, __u64 off)
{
	struct minix_super_block *ms;

	dbg("probing at offset 0x%llx", (unsigned long long) off);

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
