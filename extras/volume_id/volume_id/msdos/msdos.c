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

#include "../volume_id.h"
#include "../logging.h"
#include "../util.h"
#include "msdos.h"

#define MSDOS_MAGIC			"\x55\xaa"
#define MSDOS_PARTTABLE_OFFSET		0x1be
#define MSDOS_SIG_OFF			0x1fe
#define BSIZE				0x200
#define DOS_EXTENDED_PARTITION		0x05
#define LINUX_EXTENDED_PARTITION	0x85
#define WIN98_EXTENDED_PARTITION	0x0f
#define LINUX_RAID_PARTITION		0xfd
#define is_extended(type) \
	(type == DOS_EXTENDED_PARTITION ||	\
	 type == WIN98_EXTENDED_PARTITION ||	\
	 type == LINUX_EXTENDED_PARTITION)
#define is_raid(type) \
	(type == LINUX_RAID_PARTITION)

int volume_id_probe_msdos_part_table(struct volume_id *id, __u64 off)
{
	struct msdos_partition_entry {
		__u8	boot_ind;
		__u8	head;
		__u8	sector;
		__u8	cyl;
		__u8	sys_ind;
		__u8	end_head;
		__u8	end_sector;
		__u8	end_cyl;
		__u32	start_sect;
		__u32	nr_sects;
	} __attribute__((packed)) *part;

	const __u8 *buf;
	int i;
	__u64 poff;
	__u64 plen;
	__u64 extended = 0;
	__u64 current;
	__u64 next;
	int limit;
	int empty = 1;
	struct volume_id_partition *p;

	buf = volume_id_get_buffer(id, off, 0x200);
	if (buf == NULL)
		return -1;

	if (strncmp(&buf[MSDOS_SIG_OFF], MSDOS_MAGIC, 2) != 0)
		return -1;

	/* check flags on all entries for a valid partition table */
	part = (struct msdos_partition_entry*) &buf[MSDOS_PARTTABLE_OFFSET];
	for (i = 0; i < 4; i++) {
		if (part[i].boot_ind != 0 &&
		    part[i].boot_ind != 0x80)
			return -1;

		if (le32_to_cpu(part[i].nr_sects) != 0)
			empty = 0;
	}
	if (empty == 1)
		return -1;

	if (id->partitions != NULL)
		free(id->partitions);
	id->partitions = malloc(VOLUME_ID_PARTITIONS_MAX *
				sizeof(struct volume_id_partition));
	if (id->partitions == NULL)
		return -1;
	memset(id->partitions, 0x00,
	       VOLUME_ID_PARTITIONS_MAX * sizeof(struct volume_id_partition));

	for (i = 0; i < 4; i++) {
		poff = (__u64) le32_to_cpu(part[i].start_sect) * BSIZE;
		plen = (__u64) le32_to_cpu(part[i].nr_sects) * BSIZE;

		if (plen == 0)
			continue;

		p = &id->partitions[i];

		p->partition_type_raw = part[i].sys_ind;

		if (is_extended(part[i].sys_ind)) {
			dbg("found extended partition at 0x%llx", poff);
			volume_id_set_usage_part(p, VOLUME_ID_PARTITIONTABLE);
			p->type = "msdos_extended_partition";
			if (extended == 0)
				extended = off + poff;
		} else {
			dbg("found 0x%x data partition at 0x%llx, len 0x%llx",
			    part[i].sys_ind, poff, plen);

			if (is_raid(part[i].sys_ind))
				volume_id_set_usage_part(p, VOLUME_ID_RAID);
			else
				volume_id_set_usage_part(p, VOLUME_ID_UNPROBED);
		}

		p->off = off + poff;
		p->len = plen;
		id->partition_count = i+1;
	}

	next = extended;
	current = extended;
	limit = 50;

	/* follow extended partition chain and add data partitions */
	while (next != 0) {
		if (limit-- == 0) {
			dbg("extended chain limit reached");
			break;
		}

		buf = volume_id_get_buffer(id, current, 0x200);
		if (buf == NULL)
			break;

		part = (struct msdos_partition_entry*) &buf[MSDOS_PARTTABLE_OFFSET];

		if (strncmp(&buf[MSDOS_SIG_OFF], MSDOS_MAGIC, 2) != 0)
			break;

		next = 0;

		for (i = 0; i < 4; i++) {
			poff = (__u64) le32_to_cpu(part[i].start_sect) * BSIZE;
			plen = (__u64) le32_to_cpu(part[i].nr_sects) * BSIZE;

			if (plen == 0)
				continue;

			if (is_extended(part[i].sys_ind)) {
				dbg("found extended partition at 0x%llx", poff);
				if (next == 0)
					next = extended + poff;
			} else {
				dbg("found 0x%x data partition at 0x%llx, len 0x%llx",
					part[i].sys_ind, poff, plen);

				/* we always start at the 5th entry */
				while (id->partition_count < 4)
					volume_id_set_usage_part(&id->partitions[id->partition_count++], VOLUME_ID_UNUSED);

				p = &id->partitions[id->partition_count];

				if (is_raid(part[i].sys_ind))
					volume_id_set_usage_part(p, VOLUME_ID_RAID);
				else
					volume_id_set_usage_part(p, VOLUME_ID_UNPROBED);

				p->off = current + poff;
				p->len = plen;
				id->partition_count++;

				p->partition_type_raw = part[i].sys_ind;

				if (id->partition_count >= VOLUME_ID_PARTITIONS_MAX) {
					dbg("too many partitions");
					next = 0;
				}
			}
		}

		current = next;
	}

	volume_id_set_usage(id, VOLUME_ID_PARTITIONTABLE);
	id->type = "msdos_partition_table";

	return 0;
}
