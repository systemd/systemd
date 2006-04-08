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

struct silicon_meta {
	uint8_t		unknown0[0x2E];
	uint8_t		ascii_version[0x36 - 0x2E];
	uint8_t		diskname[0x56 - 0x36];
	uint8_t		unknown1[0x60 - 0x56];
	uint32_t	magic;
	uint32_t	unknown1a[0x6C - 0x64];
	uint32_t	array_sectors_low;
	uint32_t	array_sectors_high;
	uint8_t		unknown2[0x78 - 0x74];
	uint32_t	thisdisk_sectors;
	uint8_t		unknown3[0x100 - 0x7C];
	uint8_t		unknown4[0x104 - 0x100];
	uint16_t	product_id;
	uint16_t	vendor_id;
	uint16_t	minor_ver;
	uint16_t	major_ver;
} PACKED;

#define SILICON_MAGIC		0x2F000000

int volume_id_probe_silicon_medley_raid(struct volume_id *id, uint64_t off, uint64_t size)
{
	const uint8_t *buf;
	uint64_t meta_off;
	struct silicon_meta *sil;

	info("probing at offset 0x%llx, size 0x%llx",
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
