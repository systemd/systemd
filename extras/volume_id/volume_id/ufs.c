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
#include "ufs.h"

struct ufs_super_block {
	__u32	fs_link;
	__u32	fs_rlink;
	__u32	fs_sblkno;
	__u32	fs_cblkno;
	__u32	fs_iblkno;
	__u32	fs_dblkno;
	__u32	fs_cgoffset;
	__u32	fs_cgmask;
	__u32	fs_time;
	__u32	fs_size;
	__u32	fs_dsize;
	__u32	fs_ncg;	
	__u32	fs_bsize;
	__u32	fs_fsize;
	__u32	fs_frag;
	__u32	fs_minfree;
	__u32	fs_rotdelay;
	__u32	fs_rps;	
	__u32	fs_bmask;
	__u32	fs_fmask;
	__u32	fs_bshift;
	__u32	fs_fshift;
	__u32	fs_maxcontig;
	__u32	fs_maxbpg;
	__u32	fs_fragshift;
	__u32	fs_fsbtodb;
	__u32	fs_sbsize;
	__u32	fs_csmask;
	__u32	fs_csshift;
	__u32	fs_nindir;
	__u32	fs_inopb;
	__u32	fs_nspf;
	__u32	fs_optim;
	__u32	fs_npsect_state;
	__u32	fs_interleave;
	__u32	fs_trackskew;
	__u32	fs_id[2];
	__u32	fs_csaddr;
	__u32	fs_cssize;
	__u32	fs_cgsize;
	__u32	fs_ntrak;
	__u32	fs_nsect;
	__u32	fs_spc;	
	__u32	fs_ncyl;
	__u32	fs_cpg;
	__u32	fs_ipg;
	__u32	fs_fpg;
	struct ufs_csum {
		__u32	cs_ndir;
		__u32	cs_nbfree;
		__u32	cs_nifree;
		__u32	cs_nffree;
	} __attribute__((__packed__)) fs_cstotal;
	__s8	fs_fmod;
	__s8	fs_clean;
	__s8	fs_ronly;
	__s8	fs_flags;
	union {
		struct {
			__s8	fs_fsmnt[512];
			__u32	fs_cgrotor;
			__u32	fs_csp[31];
			__u32	fs_maxcluster;
			__u32	fs_cpc;
			__u16	fs_opostbl[16][8];
		} __attribute__((__packed__)) fs_u1;
		struct {
			__s8	fs_fsmnt[468];
			__u8	fs_volname[32];
			__u64	fs_swuid;
			__s32	fs_pad;
			__u32	fs_cgrotor;
			__u32	fs_ocsp[28];
			__u32	fs_contigdirs;
			__u32	fs_csp;	
			__u32	fs_maxcluster;
			__u32	fs_active;
			__s32	fs_old_cpc;
			__s32	fs_maxbsize;
			__s64	fs_sparecon64[17];
			__s64	fs_sblockloc;
			struct ufs2_csum_total {
				__u64	cs_ndir;
				__u64	cs_nbfree;
				__u64	cs_nifree;
				__u64	cs_nffree;
				__u64	cs_numclusters;
				__u64	cs_spare[3];
			} __attribute__((__packed__)) fs_cstotal;
			struct ufs_timeval {
				__s32	tv_sec;
				__s32	tv_usec;
			} __attribute__((__packed__)) fs_time;
			__s64	fs_size;
			__s64	fs_dsize;
			__u64	fs_csaddr;
			__s64	fs_pendingblocks;
			__s32	fs_pendinginodes;
		} __attribute__((__packed__)) fs_u2;
	}  fs_u11;
	union {
		struct {
			__s32	fs_sparecon[53];
			__s32	fs_reclaim;
			__s32	fs_sparecon2[1];
			__s32	fs_state;
			__u32	fs_qbmask[2];
			__u32	fs_qfmask[2];
		} __attribute__((__packed__)) fs_sun;
		struct {
			__s32	fs_sparecon[53];
			__s32	fs_reclaim;
			__s32	fs_sparecon2[1];
			__u32	fs_npsect;
			__u32	fs_qbmask[2];
			__u32	fs_qfmask[2];
		} __attribute__((__packed__)) fs_sunx86;
		struct {
			__s32	fs_sparecon[50];
			__s32	fs_contigsumsize;
			__s32	fs_maxsymlinklen;
			__s32	fs_inodefmt;
			__u32	fs_maxfilesize[2];
			__u32	fs_qbmask[2];
			__u32	fs_qfmask[2];
			__s32	fs_state;
		} __attribute__((__packed__)) fs_44;
	} fs_u2;
	__s32	fs_postblformat;
	__s32	fs_nrpos;
	__s32	fs_postbloff;
	__s32	fs_rotbloff;
	__u32	fs_magic;
	__u8	fs_space[1];
} __attribute__((__packed__));

#define UFS_MAGIC			0x00011954
#define UFS2_MAGIC			0x19540119
#define UFS_MAGIC_FEA			0x00195612
#define UFS_MAGIC_LFN			0x00095014

int volume_id_probe_ufs(struct volume_id *id, __u64 off)
{
	__u32	magic;
	int 	i;
	struct ufs_super_block *ufs;
	int	offsets[] = {0, 8, 64, 256, -1};

	dbg("probing at offset %llu", off);

	for (i = 0; offsets[i] >= 0; i++) {	
		ufs = (struct ufs_super_block *) volume_id_get_buffer(id, off + (offsets[i] * 0x400), 0x800);
		if (ufs == NULL)
			return -1;

		dbg("offset 0x%x", offsets[i] * 0x400);
		magic = be32_to_cpu(ufs->fs_magic);
		if ((magic == UFS_MAGIC) ||
		    (magic == UFS2_MAGIC) ||
		    (magic == UFS_MAGIC_FEA) ||
		    (magic == UFS_MAGIC_LFN)) {
			dbg("magic 0x%08x(be)", magic);
			goto found;
		}
		magic = le32_to_cpu(ufs->fs_magic);
		if ((magic == UFS_MAGIC) ||
		    (magic == UFS2_MAGIC) ||
		    (magic == UFS_MAGIC_FEA) ||
		    (magic == UFS_MAGIC_LFN)) {
			dbg("magic 0x%08x(le)", magic);
			goto found;
		}
	}
	return -1;

found:
	volume_id_set_usage(id, VOLUME_ID_FILESYSTEM);
	id->type = "ufs";

	return 0;
}
