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
#include "lvm.h"

struct lvm1_super_block {
	__u8	id[2];
} __attribute__((packed));

struct lvm2_super_block {
	__u8	id[8];
	__u64	sector_xl;
	__u32	crc_xl;
	__u32	offset_xl;
	__u8	type[8];
} __attribute__((packed));

#define LVM1_SB_OFF			0x400
#define LVM1_MAGIC			"HM"

int volume_id_probe_lvm1(struct volume_id *id, __u64 off)
{
	const __u8 *buf;
	struct lvm1_super_block *lvm;

	dbg("probing at offset %llu", off);

	buf = volume_id_get_buffer(id, off + LVM1_SB_OFF, 0x800);
	if (buf == NULL)
		return -1;

	lvm = (struct lvm1_super_block *) buf;

	if (memcmp(lvm->id, LVM1_MAGIC, 2) != 0)
		return -1;

	volume_id_set_usage(id, VOLUME_ID_RAID);
	id->type = "LVM1_member";

	return 0;
}

#define LVM2_LABEL_ID			"LABELONE"
#define LVM2LABEL_SCAN_SECTORS		4

int volume_id_probe_lvm2(struct volume_id *id, __u64 off)
{
	const __u8 *buf;
	unsigned int soff;
	struct lvm2_super_block *lvm;

	dbg("probing at offset %llu", off);

	buf = volume_id_get_buffer(id, off, LVM2LABEL_SCAN_SECTORS * 0x200);
	if (buf == NULL)
		return -1;


	for (soff = 0; soff < LVM2LABEL_SCAN_SECTORS * 0x200; soff += 0x200) {
		lvm = (struct lvm2_super_block *) &buf[soff];

		if (memcmp(lvm->id, LVM2_LABEL_ID, 8) == 0)
			goto found;
	}

	return -1;

found:
	strncpy(id->type_version, lvm->type, 8);
	volume_id_set_usage(id, VOLUME_ID_RAID);
	id->type = "LVM2_member";

	return 0;
}
