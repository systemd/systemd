/*
 * volume_id - reads filesystem label and uuid
 *
 * Copyright (C) 2004 Kay Sievers <kay.sievers@vrfy.org>
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation; either
 *	version 2.1 of the License, or (at your option) any later version.
 *
 *	This library is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *	Lesser General Public License for more details.
 *
 *	You should have received a copy of the GNU Lesser General Public
 *	License along with this library; if not, write to the Free Software
 *	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
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
#include <asm/types.h>

#include "volume_id.h"
#include "logging.h"
#include "util.h"
#include "linux_raid.h"

struct mdp_super_block {
	__u32	md_magic;
	__u32	major_version;
	__u32	minor_version;
	__u32	patch_version;
	__u32	gvalid_words;
	__u32	set_uuid0;
	__u32	ctime;
	__u32	level;
	__u32	size;
	__u32	nr_disks;
	__u32	raid_disks;
	__u32	md_minor;
	__u32	not_persistent;
	__u32	set_uuid1;
	__u32	set_uuid2;
	__u32	set_uuid3;
} __attribute__((packed)) *mdp;

#define MD_RESERVED_BYTES		0x10000
#define MD_MAGIC			0xa92b4efc

int volume_id_probe_linux_raid(struct volume_id *id, __u64 off, __u64 size)
{
	const __u8 *buf;
	__u64 sboff;
	__u8 uuid[16];

	dbg("probing at offset %llu", off);

	if (size < 0x10000)
		return -1;

	sboff = (size & ~(MD_RESERVED_BYTES - 1)) - MD_RESERVED_BYTES;
	buf = volume_id_get_buffer(id, off + sboff, 0x800);
	if (buf == NULL)
		return -1;

	mdp = (struct mdp_super_block *) buf;

	if (le32_to_cpu(mdp->md_magic) != MD_MAGIC)
		return -1;

	memcpy(uuid, &mdp->set_uuid0, 4);
	memcpy(&uuid[4], &mdp->set_uuid1, 12);
	volume_id_set_uuid(id, uuid, UUID_DCE);

	snprintf(id->type_version, VOLUME_ID_FORMAT_SIZE-1, "%u.%u.%u",
		 le32_to_cpu(mdp->major_version),
		 le32_to_cpu(mdp->minor_version),
		 le32_to_cpu(mdp->patch_version));

	dbg("found raid signature");
	volume_id_set_usage(id, VOLUME_ID_RAID);
	id->type = "linux_raid_member";

	return 0;
}
