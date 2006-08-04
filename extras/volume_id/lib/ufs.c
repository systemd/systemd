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

struct ufs_super_block {
	uint32_t	fs_link;
	uint32_t	fs_rlink;
	uint32_t	fs_sblkno;
	uint32_t	fs_cblkno;
	uint32_t	fs_iblkno;
	uint32_t	fs_dblkno;
	uint32_t	fs_cgoffset;
	uint32_t	fs_cgmask;
	uint32_t	fs_time;
	uint32_t	fs_size;
	uint32_t	fs_dsize;
	uint32_t	fs_ncg;	
	uint32_t	fs_bsize;
	uint32_t	fs_fsize;
	uint32_t	fs_frag;
	uint32_t	fs_minfree;
	uint32_t	fs_rotdelay;
	uint32_t	fs_rps;	
	uint32_t	fs_bmask;
	uint32_t	fs_fmask;
	uint32_t	fs_bshift;
	uint32_t	fs_fshift;
	uint32_t	fs_maxcontig;
	uint32_t	fs_maxbpg;
	uint32_t	fs_fragshift;
	uint32_t	fs_fsbtodb;
	uint32_t	fs_sbsize;
	uint32_t	fs_csmask;
	uint32_t	fs_csshift;
	uint32_t	fs_nindir;
	uint32_t	fs_inopb;
	uint32_t	fs_nspf;
	uint32_t	fs_optim;
	uint32_t	fs_npsect_state;
	uint32_t	fs_interleave;
	uint32_t	fs_trackskew;
	uint32_t	fs_id[2];
	uint32_t	fs_csaddr;
	uint32_t	fs_cssize;
	uint32_t	fs_cgsize;
	uint32_t	fs_ntrak;
	uint32_t	fs_nsect;
	uint32_t	fs_spc;	
	uint32_t	fs_ncyl;
	uint32_t	fs_cpg;
	uint32_t	fs_ipg;
	uint32_t	fs_fpg;
	struct ufs_csum {
		uint32_t	cs_ndir;
		uint32_t	cs_nbfree;
		uint32_t	cs_nifree;
		uint32_t	cs_nffree;
	} PACKED fs_cstotal;
	int8_t		fs_fmod;
	int8_t		fs_clean;
	int8_t		fs_ronly;
	int8_t		fs_flags;
	union {
		struct {
			int8_t	fs_fsmnt[512];
			uint32_t	fs_cgrotor;
			uint32_t	fs_csp[31];
			uint32_t	fs_maxcluster;
			uint32_t	fs_cpc;
			uint16_t	fs_opostbl[16][8];
		} PACKED fs_u1;
		struct {
			int8_t		fs_fsmnt[468];
			uint8_t		fs_volname[32];
			uint64_t	fs_swuid;
			int32_t		fs_pad;
			uint32_t	fs_cgrotor;
			uint32_t	fs_ocsp[28];
			uint32_t	fs_contigdirs;
			uint32_t	fs_csp;	
			uint32_t	fs_maxcluster;
			uint32_t	fs_active;
			int32_t		fs_old_cpc;
			int32_t		fs_maxbsize;
			int64_t		fs_sparecon64[17];
			int64_t		fs_sblockloc;
			struct ufs2_csum_total {
				uint64_t	cs_ndir;
				uint64_t	cs_nbfree;
				uint64_t	cs_nifree;
				uint64_t	cs_nffree;
				uint64_t	cs_numclusters;
				uint64_t	cs_spare[3];
			} PACKED fs_cstotal;
			struct ufs_timeval {
				int32_t		tv_sec;
				int32_t		tv_usec;
			} PACKED fs_time;
			int64_t		fs_size;
			int64_t		fs_dsize;
			uint64_t	fs_csaddr;
			int64_t		fs_pendingblocks;
			int32_t		fs_pendinginodes;
		} PACKED fs_u2;
	}  fs_u11;
	union {
		struct {
			int32_t		fs_sparecon[53];
			int32_t		fs_reclaim;
			int32_t		fs_sparecon2[1];
			int32_t		fs_state;
			uint32_t	fs_qbmask[2];
			uint32_t	fs_qfmask[2];
		} PACKED fs_sun;
		struct {
			int32_t		fs_sparecon[53];
			int32_t		fs_reclaim;
			int32_t		fs_sparecon2[1];
			uint32_t	fs_npsect;
			uint32_t	fs_qbmask[2];
			uint32_t	fs_qfmask[2];
		} PACKED fs_sunx86;
		struct {
			int32_t		fs_sparecon[50];
			int32_t		fs_contigsumsize;
			int32_t		fs_maxsymlinklen;
			int32_t		fs_inodefmt;
			uint32_t	fs_maxfilesize[2];
			uint32_t	fs_qbmask[2];
			uint32_t	fs_qfmask[2];
			int32_t		fs_state;
		} PACKED fs_44;
	} fs_u2;
	int32_t		fs_postblformat;
	int32_t		fs_nrpos;
	int32_t		fs_postbloff;
	int32_t		fs_rotbloff;
	uint32_t	fs_magic;
	uint8_t		fs_space[1];
} PACKED;

#define UFS_MAGIC			0x00011954
#define UFS2_MAGIC			0x19540119
#define UFS_MAGIC_FEA			0x00195612
#define UFS_MAGIC_LFN			0x00095014

int volume_id_probe_ufs(struct volume_id *id, uint64_t off, uint64_t size)
{
	uint32_t magic;
	int i;
	struct ufs_super_block *ufs;
	int offsets[] = {0, 8, 64, 256, -1};

	info("probing at offset 0x%llx", (unsigned long long) off);

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
	switch (magic) {
	case UFS_MAGIC:
		strcpy(id->type_version, "1");
		break;
	case UFS2_MAGIC:
		strcpy(id->type_version, "2");
		volume_id_set_label_raw(id, ufs->fs_u11.fs_u2.fs_volname, 32);
		volume_id_set_label_string(id, ufs->fs_u11.fs_u2.fs_volname, 32);
		break;
	default:
		break;
	}

	return 0;
}
