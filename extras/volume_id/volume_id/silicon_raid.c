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
#include "silicon_raid.h"

struct silicon_meta {
	__u8	unknown0[0x2E];
	__u8	ascii_version[0x36 - 0x2E];
	__u8	diskname[0x56 - 0x36];
	__u8	unknown1[0x60 - 0x56];
	__u32	magic;
	__u32	unknown1a[0x6C - 0x64];
	__u32	array_sectors_low;
	__u32	array_sectors_high;
	__u8	unknown2[0x78 - 0x74];
	__u32	thisdisk_sectors;
	__u8	unknown3[0x100 - 0x7C];
	__u8	unknown4[0x104 - 0x100];
	__u16	product_id;
	__u16	vendor_id;
	__u16	minor_ver;
	__u16	major_ver;
} __attribute__((packed));

#define SILICON_MAGIC		0x2F000000

int volume_id_probe_silicon_medley_raid(struct volume_id *id, __u64 off, __u64 size)
{
	const __u8 *buf;
	__u64 meta_off;
	struct silicon_meta *sil;

	dbg("probing at offset 0x%llx, size 0x%llx",
	    (unsigned long long) off, (unsigned long long) size);

	if (size < 0x10000)
		return -1;

	meta_off = ((size / 0x200)-1) * 0x200;
	buf = volume_id_get_buffer(id, off + meta_off, 0x200);
	if (buf == NULL)
		return -1;

	sil = (struct silicon_meta *) buf;
	if (le32_to_cpu(sil->magic) != SILICON_MAGIC)
		return -1;

	volume_id_set_usage(id, VOLUME_ID_RAID);
	snprintf(id->type_version, sizeof(id->type_version)-1, "%u.%u",
		 le16_to_cpu(sil->major_ver), le16_to_cpu(sil->minor_ver));
	id->type = "silicon_medley_raid_member";

	return 0;
}
