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
#include "logging.h"
#include "util.h"

struct via_meta {
	uint16_t	signature;
	uint8_t		version_number;
	struct via_array {
		uint16_t	disk_bits;
		uint8_t		disk_array_ex;
		uint32_t	capacity_low;
		uint32_t	capacity_high;
		uint32_t	serial_checksum;
	} PACKED array;
	uint32_t	serial_checksum[8];
	uint8_t		checksum;
} PACKED;

#define VIA_SIGNATURE		0xAA55

int volume_id_probe_via_raid(struct volume_id *id, uint64_t off, uint64_t size)
{
	const uint8_t *buf;
	uint64_t meta_off;
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
