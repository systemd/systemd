/*
 * volume_id - reads filesystem label and uuid
 *
 * Copyright (C) 2007 Kay Sievers <kay.sievers@vrfy.org>
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
#include <byteswap.h>

#include "libvolume_id.h"
#include "util.h"

/* http://www.snia.org/standards/home */

#define DDF_HEADER			0xDE11DE11
#define DDF_GUID_LENGTH			24
#define DDF_REV_LENGTH			8

static struct ddf_header {
	uint32_t	signature;
	uint32_t	crc;
	uint8_t		guid[DDF_GUID_LENGTH];
	uint8_t		ddf_rev[DDF_REV_LENGTH];
} PACKED *ddf;

int volume_id_probe_ddf_raid(struct volume_id *id, uint64_t off, uint64_t size)
{
	uint64_t ddf_off = ((size / 0x200)-1) * 0x200;
	const uint8_t *buf;

	info("probing at offset 0x%llx, size 0x%llx",
	    (unsigned long long) off, (unsigned long long) size);
	if (size < 0x10000)
		return -1;

	buf = volume_id_get_buffer(id, off + ddf_off, 0x200);
	if (buf == NULL)
		return -1;
	ddf = (struct ddf_header *) buf;

	if (ddf->signature != cpu_to_be32(DDF_HEADER))
		return -1;

	volume_id_set_uuid(id, ddf->guid, DDF_GUID_LENGTH, UUID_STRING);
	snprintf(id->type_version, DDF_REV_LENGTH, "%s", ddf->ddf_rev);
	volume_id_set_usage(id, VOLUME_ID_RAID);
	id->type = "ddf_raid_member";
	return 0;
}
