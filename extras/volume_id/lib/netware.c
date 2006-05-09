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

#define NW_SUPERBLOCK_OFFSET			0x1000

struct netware_super_block {
	uint8_t		SBH_Signature[4];
	uint16_t	SBH_VersionMajor;
	uint16_t	SBH_VersionMinor;
	uint16_t	SBH_VersionMediaMajor;
	uint16_t	SBH_VersionMediaMinor;
	uint32_t	SBH_ItemsMoved;
	uint8_t		SBH_InternalID[16];
} PACKED;

int volume_id_probe_netware(struct volume_id *id, uint64_t off)
{
	struct netware_super_block *nw;

	info("probing at offset 0x%llx", (unsigned long long) off);

	nw = (struct netware_super_block *) volume_id_get_buffer(id, off + NW_SUPERBLOCK_OFFSET, 0x200);
	if (nw == NULL)
		return -1;

	if (memcmp(nw->SBH_Signature, "SPB5", 4) != 0)
		return -1;

	volume_id_set_uuid(id, nw->SBH_InternalID, UUID_DCE);

	snprintf(id->type_version, sizeof(id->type_version)-1, "%u.%02u",
		 le16_to_cpu(nw->SBH_VersionMediaMajor), le16_to_cpu(nw->SBH_VersionMediaMinor));

	volume_id_set_usage(id, VOLUME_ID_FILESYSTEM);
	id->type = "nss";

	return 0;
}
