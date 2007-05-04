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
#include <byteswap.h>

#include "libvolume_id.h"
#include "util.h"

static struct mdp0_super_block {
	uint32_t	md_magic;
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
} PACKED *mdp0;

struct mdp1_super_block {
	uint32_t	magic;
	uint32_t	major_version;
	uint32_t	feature_map;
	uint32_t	pad0;
	uint8_t		set_uuid[16];
	uint8_t		set_name[32];
} PACKED *mdp1;

#define MD_RESERVED_BYTES		0x10000
#define MD_SB_MAGIC			0xa92b4efc

static int volume_id_probe_linux_raid0(struct volume_id *id, uint64_t off, uint64_t size)
{
	const uint8_t *buf;
	union {
		uint32_t ints[4];
		uint8_t bytes[16];
	} uuid;

	info("probing at offset 0x%llx, size 0x%llx",
	    (unsigned long long) off, (unsigned long long) size);
	if (size < 0x10000)
		return -1;

	buf = volume_id_get_buffer(id, off, 0x800);
	if (buf == NULL)
		return -1;
	mdp0 = (struct mdp0_super_block *) buf;

	if (le32_to_cpu(mdp0->md_magic) == MD_SB_MAGIC) {
		uuid.ints[0] = bswap_32(mdp0->set_uuid0);
		if (le32_to_cpu(mdp0->minor_version >= 90)) {
			uuid.ints[1] = bswap_32(mdp0->set_uuid1);
			uuid.ints[2] = bswap_32(mdp0->set_uuid2);
			uuid.ints[3] = bswap_32(mdp0->set_uuid3);
		} else {
			uuid.ints[1] = 0;
			uuid.ints[2] = 0;
			uuid.ints[3] = 0;
		}
		volume_id_set_uuid(id, uuid.bytes, 0, UUID_FOURINT);
		snprintf(id->type_version, sizeof(id->type_version)-1, "%u.%u.%u",
			 le32_to_cpu(mdp0->major_version),
			 le32_to_cpu(mdp0->minor_version),
			 le32_to_cpu(mdp0->patch_version));
	} else if (be32_to_cpu(mdp0->md_magic) == MD_SB_MAGIC) {
		uuid.ints[0] = mdp0->set_uuid0;
		if (be32_to_cpu(mdp0->minor_version >= 90)) {
			uuid.ints[1] = mdp0->set_uuid1;
			uuid.ints[2] = mdp0->set_uuid2;
			uuid.ints[3] = mdp0->set_uuid3;
		} else {
			uuid.ints[1] = 0;
			uuid.ints[2] = 0;
			uuid.ints[3] = 0;
		}
		volume_id_set_uuid(id, uuid.bytes, 0, UUID_FOURINT);
		snprintf(id->type_version, sizeof(id->type_version)-1, "%u.%u.%u",
			 be32_to_cpu(mdp0->major_version),
			 be32_to_cpu(mdp0->minor_version),
			 be32_to_cpu(mdp0->patch_version));
	} else
		return -1;

	volume_id_set_usage(id, VOLUME_ID_RAID);
	id->type = "linux_raid_member";
	return 0;
}

static int volume_id_probe_linux_raid1(struct volume_id *id, uint64_t off, uint64_t size)
{
	const uint8_t *buf;

	info("probing at offset 0x%llx, size 0x%llx",
	    (unsigned long long) off, (unsigned long long) size);

	buf = volume_id_get_buffer(id, off, 0x800);
	if (buf == NULL)
		return -1;
	mdp1 = (struct mdp1_super_block *) buf;

	if (le32_to_cpu(mdp1->magic) != MD_SB_MAGIC)
		return -1;

	volume_id_set_uuid(id, mdp1->set_uuid, 0, UUID_FOURINT);
	volume_id_set_label_raw(id, mdp1->set_name, 32);
	volume_id_set_label_string(id, mdp1->set_name, 32);
	snprintf(id->type_version, sizeof(id->type_version)-1, "%u", le32_to_cpu(mdp1->major_version));
	volume_id_set_usage(id, VOLUME_ID_RAID);
	id->type = "linux_raid_member";
	return 0;
}

int volume_id_probe_linux_raid(struct volume_id *id, uint64_t off, uint64_t size)
{
	uint64_t sboff = (size & ~(MD_RESERVED_BYTES - 1)) - MD_RESERVED_BYTES;

	/* version 0 at the end of the device */
	if (volume_id_probe_linux_raid0(id, off + sboff, size) == 0)
		return 0;

	/* version 1.0 at the end of the device */
	if (volume_id_probe_linux_raid1(id, off + sboff, size) == 0)
		return 0;

	/* version 1.1 at the start of the device */
	if (volume_id_probe_linux_raid1(id, off, size) == 0)
		return 0;

	/* version 1.2 at 4k offset from the start */
	if (volume_id_probe_linux_raid1(id, off + 0x1000, size) == 0)
		return 0;

	return -1;
}
