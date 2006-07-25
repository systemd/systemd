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

struct volume_descriptor {
	struct descriptor_tag {
		uint16_t	id;
		uint16_t	version;
		uint8_t		checksum;
		uint8_t		reserved;
		uint16_t	serial;
		uint16_t	crc;
		uint16_t	crc_len;
		uint32_t	location;
	} PACKED tag;
	union {
		struct anchor_descriptor {
			uint32_t	length;
			uint32_t	location;
		} PACKED anchor;
		struct primary_descriptor {
			uint32_t	seq_num;
			uint32_t	desc_num;
			struct dstring {
				uint8_t	clen;
				uint8_t	c[31];
			} PACKED ident;
		} PACKED primary;
	} PACKED type;
} PACKED;

struct volume_structure_descriptor {
	uint8_t		type;
	uint8_t		id[5];
	uint8_t		version;
} PACKED;

#define UDF_VSD_OFFSET			0x8000

int volume_id_probe_udf(struct volume_id *id, uint64_t off, uint64_t size)
{
	struct volume_descriptor *vd;
	struct volume_structure_descriptor *vsd;
	unsigned int bs;
	unsigned int b;
	unsigned int type;
	unsigned int count;
	unsigned int loc;
	unsigned int clen;

	info("probing at offset 0x%llx", (unsigned long long) off);

	vsd = (struct volume_structure_descriptor *) volume_id_get_buffer(id, off + UDF_VSD_OFFSET, 0x200);
	if (vsd == NULL)
		return -1;

	if (memcmp(vsd->id, "NSR02", 5) == 0)
		goto blocksize;
	if (memcmp(vsd->id, "NSR03", 5) == 0)
		goto blocksize;
	if (memcmp(vsd->id, "BEA01", 5) == 0)
		goto blocksize;
	if (memcmp(vsd->id, "BOOT2", 5) == 0)
		goto blocksize;
	if (memcmp(vsd->id, "CD001", 5) == 0)
		goto blocksize;
	if (memcmp(vsd->id, "CDW02", 5) == 0)
		goto blocksize;
	if (memcmp(vsd->id, "TEA03", 5) == 0)
		goto blocksize;
	return -1;

blocksize:
	/* search the next VSD to get the logical block size of the volume */
	for (bs = 0x800; bs < 0x8000; bs += 0x800) {
		vsd = (struct volume_structure_descriptor *) volume_id_get_buffer(id, off + UDF_VSD_OFFSET + bs, 0x800);
		if (vsd == NULL)
			return -1;
		dbg("test for blocksize: 0x%x", bs);
		if (vsd->id[0] != '\0')
			goto nsr;
	}
	return -1;

nsr:
	/* search the list of VSDs for a NSR descriptor */
	for (b = 0; b < 64; b++) {
		vsd = (struct volume_structure_descriptor *) volume_id_get_buffer(id, off + UDF_VSD_OFFSET + (b * bs), 0x800);
		if (vsd == NULL)
			return -1;

		dbg("vsd: %c%c%c%c%c",
		    vsd->id[0], vsd->id[1], vsd->id[2], vsd->id[3], vsd->id[4]);

		if (vsd->id[0] == '\0')
			return -1;
		if (memcmp(vsd->id, "NSR02", 5) == 0)
			goto anchor;
		if (memcmp(vsd->id, "NSR03", 5) == 0)
			goto anchor;
	}
	return -1;

anchor:
	/* read anchor volume descriptor */
	vd = (struct volume_descriptor *) volume_id_get_buffer(id, off + (256 * bs), 0x200);
	if (vd == NULL)
		return -1;

	type = le16_to_cpu(vd->tag.id);
	if (type != 2) /* TAG_ID_AVDP */
		goto found;

	/* get desriptor list address and block count */
	count = le32_to_cpu(vd->type.anchor.length) / bs;
	loc = le32_to_cpu(vd->type.anchor.location);
	dbg("0x%x descriptors starting at logical secor 0x%x", count, loc);

	/* pick the primary descriptor from the list */
	for (b = 0; b < count; b++) {
		vd = (struct volume_descriptor *) volume_id_get_buffer(id, off + ((loc + b) * bs), 0x200);
		if (vd == NULL)
			return -1;

		type = le16_to_cpu(vd->tag.id);
		dbg("descriptor type %i", type);

		/* check validity */
		if (type == 0)
			goto found;
		if (le32_to_cpu(vd->tag.location) != loc + b)
			goto found;

		if (type == 1) /* TAG_ID_PVD */
			goto pvd;
	}
	goto found;

pvd:
	volume_id_set_label_raw(id, &(vd->type.primary.ident.clen), 32);

	clen = vd->type.primary.ident.clen;
	dbg("label string charsize=%i bit", clen);
	if (clen == 8)
		volume_id_set_label_string(id, vd->type.primary.ident.c, 31);
	else if (clen == 16)
		volume_id_set_label_unicode16(id, vd->type.primary.ident.c, BE,31);

found:
	volume_id_set_usage(id, VOLUME_ID_FILESYSTEM);
	id->type = "udf";

	return 0;
}
