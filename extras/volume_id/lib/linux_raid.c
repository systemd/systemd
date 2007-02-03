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

static struct mdp_super_block {
	uint8_t		md_magic[4];
	uint32_t	major_version;
	uint32_t	minor_version;
	uint32_t	patch_version;
	uint32_t	gvalid_words;
	uint32_t	set_uuid0;
	uint32_t	ctime;
	uint32_t	level;
	uint32_t	size;
	uint32_t	nr_disks;
	uint32_t	raid_disks;
	uint32_t	md_minor;
	uint32_t	not_persistent;
	uint32_t	set_uuid1;
	uint32_t	set_uuid2;
	uint32_t	set_uuid3;
} PACKED *mdp;

#define MD_RESERVED_BYTES		0x10000
#define MD_MAGIC			"\xfc\x4e\x2b\xa9"
#define MD_MAGIC_SWAP			"\xa9\x2b\x4e\xfc"

int volume_id_probe_linux_raid(struct volume_id *id, uint64_t off, uint64_t size)
{
	const uint8_t *buf;
	uint64_t sboff;
	uint8_t uuid[16];

	info("probing at offset 0x%llx, size 0x%llx",
	    (unsigned long long) off, (unsigned long long) size);
	if (size < 0x10000)
		return -1;

	sboff = (size & ~(MD_RESERVED_BYTES - 1)) - MD_RESERVED_BYTES;
	buf = volume_id_get_buffer(id, off + sboff, 0x800);
	if (buf == NULL)
		return -1;
	mdp = (struct mdp_super_block *) buf;

	if ((memcmp(mdp->md_magic, MD_MAGIC, 4) != 0) &&
	    (memcmp(mdp->md_magic, MD_MAGIC_SWAP, 4) != 0))
		return -1;

	memcpy(uuid, &mdp->set_uuid0, 4);
	memcpy(&uuid[4], &mdp->set_uuid1, 12);
	volume_id_set_uuid(id, uuid, UUID_DCE);
	snprintf(id->type_version, sizeof(id->type_version)-1, "%u.%u.%u",
		 le32_to_cpu(mdp->major_version),
		 le32_to_cpu(mdp->minor_version),
		 le32_to_cpu(mdp->patch_version));
	dbg("found raid signature");
	volume_id_set_usage(id, VOLUME_ID_RAID);
	id->type = "linux_raid_member";
	return 0;
}
