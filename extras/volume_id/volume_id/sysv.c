/*
 * volume_id - reads filesystem label and uuid
 *
 * Copyright (C) 2005 Kay Sievers <kay.sievers@vrfy.org>
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
#include "sysv.h"

#define SYSV_NICINOD			100
#define SYSV_NICFREE			50

struct sysv_super
{
	__u16	s_isize;
	__u16	s_pad0;
	__u32	s_fsize;
	__u16	s_nfree;
	__u16	s_pad1;
	__u32	s_free[SYSV_NICFREE];
	__u16	s_ninode;
	__u16	s_pad2;
	__u16	s_inode[SYSV_NICINOD];
	__u8	s_flock;
	__u8	s_ilock;
	__u8	s_fmod;
	__u8	s_ronly;
	__u32	s_time;
	__u16	s_dinfo[4];
	__u32	s_tfree;
	__u16	s_tinode;
	__u16	s_pad3;
	__u8	s_fname[6];
	__u8	s_fpack[6];
	__u32	s_fill[12];
	__u32	s_state;
	__u32	s_magic;
	__u32	s_type;
} __attribute__((__packed__));

#define XENIX_NICINOD				100
#define XENIX_NICFREE				100

struct xenix_super {
	__u16	s_isize;
	__u32	s_fsize;
	__u16	s_nfree;
	__u32	s_free[XENIX_NICFREE];
	__u16	s_ninode;
	__u16	s_inode[XENIX_NICINOD];
	__u8	s_flock;
	__u8	s_ilock;
	__u8	s_fmod;
	__u8	s_ronly;
	__u32	s_time;
	__u32	s_tfree;
	__u16	s_tinode;
	__u16	s_dinfo[4];
	__u8	s_fname[6];
	__u8	s_fpack[6];
	__u8	s_clean;
	__u8	s_fill[371];
	__u32	s_magic;
	__u32	s_type;
} __attribute__((__packed__));

#define SYSV_SUPERBLOCK_BLOCK			0x01
#define SYSV_MAGIC				0xfd187e20
#define XENIX_SUPERBLOCK_BLOCK			0x18
#define XENIX_MAGIC				0x2b5544
#define SYSV_MAX_BLOCKSIZE			0x800

int volume_id_probe_sysv(struct volume_id *id, __u64 off)
{
	struct sysv_super *vs;
	struct xenix_super *xs;
	unsigned int boff;

	dbg("probing at offset %llu", off);

	for (boff = 0x200; boff <= SYSV_MAX_BLOCKSIZE; boff <<= 1) {
		vs = (struct sysv_super *)
			volume_id_get_buffer(id, off + (boff * SYSV_SUPERBLOCK_BLOCK), 0x200);
		if (vs == NULL)
			return -1;

		if (vs->s_magic == cpu_to_le32(SYSV_MAGIC) || vs->s_magic == cpu_to_be32(SYSV_MAGIC)) {
			volume_id_set_label_raw(id, vs->s_fname, 6);
			volume_id_set_label_string(id, vs->s_fname, 6);
			id->type = "sysv";
			goto found;
		}
	}

	for (boff = 0x200; boff <= SYSV_MAX_BLOCKSIZE; boff <<= 1) {
		xs = (struct xenix_super *)
			volume_id_get_buffer(id, off + (boff + XENIX_SUPERBLOCK_BLOCK), 0x200);
		if (xs == NULL)
			return -1;

		if (xs->s_magic == cpu_to_le32(XENIX_MAGIC) || xs->s_magic == cpu_to_be32(XENIX_MAGIC)) {
			volume_id_set_label_raw(id, xs->s_fname, 6);
			volume_id_set_label_string(id, xs->s_fname, 6);
			id->type = "xenix";
			goto found;
		}
	}

	return -1;

found:
	volume_id_set_usage(id, VOLUME_ID_FILESYSTEM);
	return 0;
}
