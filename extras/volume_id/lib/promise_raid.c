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

struct promise_meta {
	uint8_t	sig[24];
} PACKED;

#define PDC_CONFIG_OFF		0x1200
#define PDC_SIGNATURE		"Promise Technology, Inc."

int volume_id_probe_promise_fasttrack_raid(struct volume_id *id, uint64_t off, uint64_t size)
{
	const uint8_t *buf;
	struct promise_meta *pdc;
	unsigned int i;
	static unsigned int sectors[] = {
		63, 255, 256, 16, 399, 0
	};

	info("probing at offset 0x%llx, size 0x%llx",
	    (unsigned long long) off, (unsigned long long) size);

	if (size < 0x40000)
		return -1;

	for (i = 0; sectors[i] != 0; i++) {
		uint64_t meta_off;

		meta_off = ((size / 0x200) - sectors[i]) * 0x200;
		buf = volume_id_get_buffer(id, off + meta_off, 0x200);
		if (buf == NULL)
			return -1;

		pdc = (struct promise_meta *) buf;
		if (memcmp(pdc->sig, PDC_SIGNATURE, sizeof(PDC_SIGNATURE)-1) == 0)
			goto found;
	}
	return -1;

found:
	volume_id_set_usage(id, VOLUME_ID_RAID);
	id->type = "promise_fasttrack_raid_member";

	return 0;
}
