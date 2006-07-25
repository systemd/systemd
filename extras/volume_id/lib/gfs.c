/*
 * volume_id - reads filesystem label and uuid
 *
 * Copyright (C) 2006 Red Hat, Inc. <redhat.com>
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

/* Common gfs/gfs2 constants: */
#define GFS_MAGIC		0x01161970
#define GFS_DEFAULT_BSIZE	4096
#define GFS_SUPERBLOCK_OFFSET	(0x10 * GFS_DEFAULT_BSIZE)
#define GFS_METATYPE_SB		1
#define GFS_FORMAT_SB		100
#define GFS_LOCKNAME_LEN	64

/* gfs1 constants: */
#define GFS_FORMAT_FS		1309
#define GFS_FORMAT_MULTI	1401
/* gfs2 constants: */
#define GFS2_FORMAT_FS		1801
#define GFS2_FORMAT_MULTI	1900

struct gfs2_meta_header {
	uint32_t mh_magic;
	uint32_t mh_type;
	uint64_t __pad0;          /* Was generation number in gfs1 */
	uint32_t mh_format;
	uint32_t __pad1;          /* Was incarnation number in gfs1 */
};

struct gfs2_inum {
	uint64_t no_formal_ino;
	uint64_t no_addr;
};

struct gfs2_sb {
	struct gfs2_meta_header sb_header;

	uint32_t sb_fs_format;
	uint32_t sb_multihost_format;
	uint32_t  __pad0;  /* Was superblock flags in gfs1 */

	uint32_t sb_bsize;
	uint32_t sb_bsize_shift;
	uint32_t __pad1;   /* Was journal segment size in gfs1 */

	struct gfs2_inum sb_master_dir; /* Was jindex dinode in gfs1 */
	struct gfs2_inum __pad2; /* Was rindex dinode in gfs1 */
	struct gfs2_inum sb_root_dir;

	char sb_lockproto[GFS_LOCKNAME_LEN];
	char sb_locktable[GFS_LOCKNAME_LEN];
	/* In gfs1, quota and license dinodes followed */
} PACKED;

static int volume_id_probe_gfs_generic(struct volume_id *id, uint64_t off, int vers)
{
	struct gfs2_sb *sbd;

	info("probing at offset 0x%llx", (unsigned long long) off);

	sbd = (struct gfs2_sb *)
		volume_id_get_buffer(id, off + GFS_SUPERBLOCK_OFFSET, sizeof(struct gfs2_sb));
	if (sbd == NULL)
		return -1;

	if (be32_to_cpu(sbd->sb_header.mh_magic) == GFS_MAGIC &&
		be32_to_cpu(sbd->sb_header.mh_type) == GFS_METATYPE_SB &&
		be32_to_cpu(sbd->sb_header.mh_format) == GFS_FORMAT_SB) {
		if (vers == 1) {
			if (be32_to_cpu(sbd->sb_fs_format) != GFS_FORMAT_FS ||
				be32_to_cpu(sbd->sb_multihost_format) != GFS_FORMAT_MULTI)
				return -1; /* not gfs1 */
			id->type = "gfs";
		}
		else if (vers == 2) {
			if (be32_to_cpu(sbd->sb_fs_format) != GFS2_FORMAT_FS ||
				be32_to_cpu(sbd->sb_multihost_format) != GFS2_FORMAT_MULTI)
				return -1; /* not gfs2 */
			id->type = "gfs2";
		}
		else
			return -1;
		strcpy(id->type_version, "1");
		volume_id_set_usage(id, VOLUME_ID_FILESYSTEM);
		return 0;
	}
	return -1;
}

int volume_id_probe_gfs(struct volume_id *id, uint64_t off, uint64_t size)
{
	return volume_id_probe_gfs_generic(id, off, 1);
}

int volume_id_probe_gfs2(struct volume_id *id, uint64_t off, uint64_t size)
{
	return volume_id_probe_gfs_generic(id, off, 2);
}
