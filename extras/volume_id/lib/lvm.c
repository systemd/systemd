/*
 * volume_id - reads filesystem label and uuid
 *
 * Copyright (C) 2004 Kay Sievers <kay.sievers@vrfy.org>
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

struct lvm1_super_block {
	uint8_t	id[2];
} PACKED;

struct lvm2_super_block {
	uint8_t		id[8];
	uint64_t	sector_xl;
	uint32_t	crc_xl;
	uint32_t	offset_xl;
	uint8_t		type[8];
} PACKED;

#define LVM1_SB_OFF			0x400
#define LVM1_MAGIC			"HM"

int volume_id_probe_lvm1(struct volume_id *id, uint64_t off, uint64_t size)
{
	const uint8_t *buf;
	struct lvm1_super_block *lvm;

	info("probing at offset 0x%llx", (unsigned long long) off);

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

int volume_id_probe_lvm2(struct volume_id *id, uint64_t off, uint64_t size)
{
	const uint8_t *buf;
	unsigned int soff;
	struct lvm2_super_block *lvm;

	dbg("probing at offset 0x%llx", (unsigned long long) off);

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
	memcpy(id->type_version, lvm->type, 8);
	volume_id_set_usage(id, VOLUME_ID_RAID);
	id->type = "LVM2_member";

	return 0;
}
