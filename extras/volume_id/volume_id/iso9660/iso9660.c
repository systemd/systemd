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
#include "iso9660.h"

#define ISO_SUPERBLOCK_OFFSET		0x8000
#define ISO_SECTOR_SIZE			0x800
#define ISO_VD_OFFSET			(ISO_SUPERBLOCK_OFFSET + ISO_SECTOR_SIZE)
#define ISO_VD_PRIMARY			0x1
#define ISO_VD_SUPPLEMENTARY		0x2
#define ISO_VD_END			0xff
#define ISO_VD_MAX			16

int volume_id_probe_iso9660(struct volume_id *id, __u64 off)
{
	union iso_super_block {
		struct iso_header {
			__u8	type;
			__u8	id[5];
			__u8	version;
			__u8	unused1;
			__u8		system_id[32];
			__u8		volume_id[32];
		} __attribute__((__packed__)) iso;
		struct hs_header {
			__u8	foo[8];
			__u8	type;
			__u8	id[4];
			__u8	version;
		} __attribute__((__packed__)) hs;
	} __attribute__((__packed__)) *is;

	is = (union iso_super_block *) volume_id_get_buffer(id, off + ISO_SUPERBLOCK_OFFSET, 0x200);
	if (is == NULL)
		return -1;

	if (strncmp(is->iso.id, "CD001", 5) == 0) {
		char root_label[VOLUME_ID_LABEL_SIZE+1];
		int vd_offset;
		int i;
		int found_svd;

		memset(root_label, 0, sizeof(root_label));
		strncpy(root_label, is->iso.volume_id, sizeof(root_label)-1);

		found_svd = 0;
		vd_offset = ISO_VD_OFFSET;
		for (i = 0; i < ISO_VD_MAX; i++) {
			is = (union iso_super_block *) volume_id_get_buffer(id, off + vd_offset, 0x200);
			if (is == NULL || is->iso.type == ISO_VD_END)
				break;
			if (is->iso.type == ISO_VD_SUPPLEMENTARY) {
				dbg("found ISO supplementary VD at offset 0x%llx", off + vd_offset);
				volume_id_set_label_raw(id, is->iso.volume_id, 32);
				volume_id_set_label_unicode16(id, is->iso.volume_id, BE, 32);
				found_svd = 1;
				break;
			}
			vd_offset += ISO_SECTOR_SIZE;
		}

		if (!found_svd ||
		    (found_svd && !strncmp(root_label, id->label, 16)))
		{
			volume_id_set_label_raw(id, root_label, 32);
			volume_id_set_label_string(id, root_label, 32);
		}
		goto found;
	}
	if (strncmp(is->hs.id, "CDROM", 5) == 0)
		goto found;
	return -1;

found:
	volume_id_set_usage(id, VOLUME_ID_FILESYSTEM);
	id->type = "iso9660";

	return 0;
}
