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
#include "highpoint.h"

struct hpt37x_meta {
	__u8	filler1[32];
	__u32	magic;
} __attribute__((packed));

struct hpt45x_meta {
	__u32	magic;
} __attribute__((packed));

#define HPT37X_CONFIG_OFF		0x1200
#define HPT37X_MAGIC_OK			0x5a7816f0
#define HPT37X_MAGIC_BAD		0x5a7816fd

#define HPT45X_MAGIC_OK			0x5a7816f3
#define HPT45X_MAGIC_BAD		0x5a7816fd


int volume_id_probe_highpoint_37x_raid(struct volume_id *id, __u64 off)
{
	const __u8 *buf;
	struct hpt37x_meta *hpt;
	__u32 magic;

	dbg("probing at offset 0x%llx", (unsigned long long) off);

	buf = volume_id_get_buffer(id, off + HPT37X_CONFIG_OFF, 0x200);
	if (buf == NULL)
		return -1;

	hpt = (struct hpt37x_meta *) buf;
	magic = le32_to_cpu(hpt->magic);
	if (magic != HPT37X_MAGIC_OK && magic != HPT37X_MAGIC_BAD)
		return -1;

	volume_id_set_usage(id, VOLUME_ID_RAID);
	id->type = "highpoint_raid_member";

	return 0;
}

int volume_id_probe_highpoint_45x_raid(struct volume_id *id, __u64 off, __u64 size)
{
	const __u8 *buf;
	struct hpt45x_meta *hpt;
	__u64 meta_off;
	__u32 magic;

	dbg("probing at offset 0x%llx, size 0x%llx",
	    (unsigned long long) off, (unsigned long long) size);

	if (size < 0x10000)
		return -1;

	meta_off = ((size / 0x200)-11) * 0x200;
	buf = volume_id_get_buffer(id, off + meta_off, 0x200);
	if (buf == NULL)
		return -1;

	hpt = (struct hpt45x_meta *) buf;
	magic = le32_to_cpu(hpt->magic);
	if (magic != HPT45X_MAGIC_OK && magic != HPT45X_MAGIC_BAD)
		return -1;

	volume_id_set_usage(id, VOLUME_ID_RAID);
	id->type = "highpoint_raid_member";

	return 0;
}
