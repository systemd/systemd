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
#include "libvolume_id-private.h"
#include "util.h"

struct oracleasm_super_block {
	uint8_t	tag[8];
	uint8_t	id[24];
} PACKED;

#define ASM_SB_OFF			0x20
#define ASM_MAGIC			"ORCLDISK"

/*
 * Detect Oracle Automatic Storage Management (ASM).
 * It can do mirroring, but don't consider it RAID in the sense
 * that an ext3 filesystem could live inside.  Thus, mark it 'other'.
 * There also is a magic word 'ORCLCLRD'; like blkid(8), we ignore that.
 */
int volume_id_probe_oracleasm(struct volume_id *id, uint64_t off, uint64_t size)
{
	const uint8_t *buf;
	struct oracleasm_super_block *oracleasm;

	info("probing at offset 0x%llx\n", (unsigned long long) off);

	buf = volume_id_get_buffer(id, off + ASM_SB_OFF, 0x800);
	if (buf == NULL)
		return -1;

	oracleasm = (struct oracleasm_super_block *) buf;

	if (memcmp(oracleasm->tag, ASM_MAGIC, 8) != 0)
		return -1;

	volume_id_set_usage(id, VOLUME_ID_OTHER);
	volume_id_set_label_raw(id, oracleasm->id, 24);
	volume_id_set_label_string(id, oracleasm->id, 24);
	id->type = "oracleasm";

	return 0;
}
