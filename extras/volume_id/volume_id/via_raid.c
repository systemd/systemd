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
#include "via_raid.h"

struct via_meta {
	__u16	signature;
	__u8	version_number;
	struct via_array {
		__u16	disk_bits;
		__u8	disk_array_ex;
		__u32	capacity_low;
		__u32	capacity_high;
		__u32	serial_checksum;
	} __attribute((packed)) array;
	__u32	serial_checksum[8];
	__u8	checksum;
} __attribute__((packed));

#define VIA_SIGNATURE		0xAA55

int volume_id_probe_via_raid(struct volume_id *id, __u64 off, __u64 size)
{
	const __u8 *buf;
	__u64 meta_off;
	struct via_meta *via;

	dbg("probing at offset 0x%llx, size 0x%llx",
	    (unsigned long long) off, (unsigned long long) size);

	if (size < 0x10000)
		return -1;

	meta_off = ((size / 0x200)-1) * 0x200;

	buf = volume_id_get_buffer(id, off + meta_off, 0x200);
	if (buf == NULL)
		return -1;

	via = (struct via_meta *) buf;
	if (le16_to_cpu(via->signature) !=  VIA_SIGNATURE)
		return -1;

	if (via->version_number > 1)
		return -1;

	volume_id_set_usage(id, VOLUME_ID_RAID);
	snprintf(id->type_version, sizeof(id->type_version)-1, "%u", via->version_number);
	id->type = "via_raid_member";

	return 0;
}
