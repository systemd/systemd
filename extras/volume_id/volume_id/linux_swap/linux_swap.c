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
#include "linux_swap.h"

struct swap_header_v1_2 {
	__u8	bootbits[1024];
	__u32	version;
	__u32	last_page;
	__u32	nr_badpages;
	__u8	uuid[16];
	__u8	volume_name[16];
} __attribute__((__packed__)) *sw;

#define LARGEST_PAGESIZE			0x4000

int volume_id_probe_linux_swap(struct volume_id *id, __u64 off)
{
	const __u8 *buf;
	unsigned int page;

	dbg("probing at offset %llu", off);

	/* the swap signature is at the end of the PAGE_SIZE */
	for (page = 0x1000; page <= LARGEST_PAGESIZE; page <<= 1) {
			buf = volume_id_get_buffer(id, off + page-10, 10);
			if (buf == NULL)
				return -1;

			if (memcmp(buf, "SWAP-SPACE", 10) == 0) {
				strcpy(id->type_version, "1");
				goto found;
			}

			if (memcmp(buf, "SWAPSPACE2", 10) == 0) {
				sw = (struct swap_header_v1_2 *) volume_id_get_buffer(id, off, sizeof(struct swap_header_v1_2));
				if (sw == NULL)
					return -1;
				strcpy(id->type_version, "2");
				volume_id_set_label_raw(id, sw->volume_name, 16);
				volume_id_set_label_string(id, sw->volume_name, 16);
				volume_id_set_uuid(id, sw->uuid, UUID_DCE);
				goto found;
			}
	}
	return -1;

found:
	volume_id_set_usage(id, VOLUME_ID_OTHER);
	id->type = "swap";

	return 0;
}
