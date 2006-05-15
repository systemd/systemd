/*
 * volume_id - reads filesystem label and uuid
 *
 * Copyright (C) 2006 Kay Sievers <kay.sievers@vrfy.org>
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

struct adaptec_meta {
	uint32_t	b0idcode;
	uint8_t		lunsave[8];
	uint16_t	sdtype;
	uint16_t	ssavecyl;
	uint8_t		ssavehed;
	uint8_t		ssavesec;
	uint8_t		sb0flags;
	uint8_t		jbodEnable;
	uint8_t		lundsave;
	uint8_t		svpdirty;
	uint16_t	biosInfo;
	uint16_t	svwbskip;
	uint16_t	svwbcln;
	uint16_t	svwbmax;
	uint16_t	res3;
	uint16_t	svwbmin;
	uint16_t	res4;
	uint16_t	svrcacth;
	uint16_t	svwcacth;
	uint16_t	svwbdly;
	uint8_t		svsdtime;
	uint8_t		res5;
	uint16_t	firmval;
	uint16_t	firmbln;
	uint32_t	firmblk;
	uint32_t	fstrsvrb;
	uint16_t	svBlockStorageTid;
	uint16_t	svtid;
	uint8_t		svseccfl;
	uint8_t		res6;
	uint8_t		svhbanum;
	uint8_t		resver;
	uint32_t	drivemagic;
	uint8_t		reserved[20];
	uint8_t		testnum;
	uint8_t		testflags;
	uint16_t	maxErrorCount;
	uint32_t	count;
	uint32_t	startTime;
	uint32_t	interval;
	uint8_t		tstxt0;
	uint8_t		tstxt1;
	uint8_t		serNum[32];
	uint8_t		res8[102];
	uint32_t	fwTestMagic;
	uint32_t	fwTestSeqNum;
	uint8_t		fwTestRes[8];
	uint8_t		smagic[4];
	uint32_t	raidtbl;
	uint16_t	raidline;
	uint8_t		res9[0xF6];
} PACKED;

int volume_id_probe_adaptec_raid(struct volume_id *id, uint64_t off, uint64_t size)
{
	const uint8_t *buf;
	uint64_t meta_off;
	struct adaptec_meta *ad;

	info("probing at offset 0x%llx, size 0x%llx",
	    (unsigned long long) off, (unsigned long long) size);

	if (size < 0x10000)
		return -1;

	meta_off = ((size / 0x200)-1) * 0x200;
	buf = volume_id_get_buffer(id, off + meta_off, 0x200);
	if (buf == NULL)
		return -1;

	ad = (struct adaptec_meta *) buf;
	if (memcmp(ad->smagic, "DPTM", 4) != 0)
		return -1;

	if (ad->b0idcode != be32_to_cpu(0x37FC4D1E))
		return -1;

	volume_id_set_usage(id, VOLUME_ID_RAID);
	snprintf(id->type_version, sizeof(id->type_version)-1, "%u", ad->resver);
	id->type = "adaptec_raid_member";

	return 0;
}
