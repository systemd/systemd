/*
 * volume_id - reads filesystem label and uuid
 *
 * Copyright (C) 2004 Kay Sievers <kay.sievers@vrfy.org>
 *
 *	The superblock structs are taken from the libblkid living inside
 *	the e2fsprogs. This is a simple straightforward implementation for
 *	reading the label strings of only the most common filesystems.
 *	If you need a full featured library with attribute caching, support for
 *	much more partition/media types or non-root data access, you may have
 *	a look at:
 *		http://e2fsprogs.sourceforge.net.
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
 *
 *	This program is distributed in the hope that it will be useful, but
 *	WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *	General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License along
 *	with this program; if not, write to the Free Software Foundation, Inc.,
 *	675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <asm/types.h>

#include "volume_id.h"


#define bswap32(x) (__u32)((((__u32)(x) & 0xff000000u) >> 24) | \
			   (((__u32)(x) & 0x00ff0000u) >>  8) | \
			   (((__u32)(x) & 0x0000ff00u) <<  8) | \
			   (((__u32)(x) & 0x000000ffu) << 24))

#if (__BYTE_ORDER == __LITTLE_ENDIAN) 
#define cpu_to_le32(x) (x)
#elif (__BYTE_ORDER == __BIG_ENDIAN)
#define cpu_to_le32(x) bswap32(x)
#endif

#define VOLUME_ID_BUFFER_SIZE		0x11000 /* reiser offset is 64k */


static void set_label(struct volume_id *id, char *buf, int count)
{
	int i;

	memcpy(id->label, buf, count);

	memcpy(id->label_string, buf, count);

	/* remove trailing whitespace */
	i = strlen(id->label_string);
	while (i--) {
		if (! isspace(id->label_string[i]))
			break;
	}
	id->label_string[i+1] = '\0';
}

static void set_uuid(struct volume_id *id, unsigned char *buf, int count)
{
	int i;

	memcpy(id->uuid, buf, count);

	/* create string if uuid is set */
	for (i = 0; i < count; i++) 
		if (buf[i] != 0)
			goto set;
	return;

set:
	switch(count) {
	case 4:
		sprintf(id->uuid_string, "%02X%02X-%02X%02X",
			buf[3], buf[2], buf[1], buf[0]);
		break;
	case 16:
		sprintf(id->uuid_string,
			"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
			buf[0], buf[1], buf[2], buf[3],
			buf[4], buf[5],
			buf[6], buf[7],
			buf[8], buf[9],
			buf[10], buf[11], buf[12], buf[13], buf[14],buf[15]);
		break;
	}
}

static int open_superblock(struct volume_id *id)
{
	/* get buffer to read the first block */
	if (id->buf == NULL) {
		id->buf = malloc(VOLUME_ID_BUFFER_SIZE);
		if (id->buf == NULL)
			return -1;
	}

	/* try to read the first 64k, but at least the first block */
	memset(id->buf, 0x00, VOLUME_ID_BUFFER_SIZE);
	lseek(id->fd, 0, SEEK_SET);
	if (read(id->fd, id->buf, VOLUME_ID_BUFFER_SIZE) < 0x200)
		return -1;

	return 0;
}

static void close_superblock(struct volume_id *id)
{
	if (id->buf != NULL) {
		free(id->buf);
		id->buf = NULL;
	}
}

#define EXT3_FEATURE_COMPAT_HAS_JOURNAL		0x00000004
#define EXT3_FEATURE_INCOMPAT_JOURNAL_DEV	0x00000008
#define EXT_SUPERBLOCK_OFFSET			0x400
static int probe_ext(struct volume_id *id)
{
	struct ext2_super_block {
		__u32		s_inodes_count;
		__u32		s_blocks_count;
		__u32		s_r_blocks_count;
		__u32		s_free_blocks_count;
		__u32		s_free_inodes_count;
		__u32		s_first_data_block;
		__u32		s_log_block_size;
		__u32		s_dummy3[7];
		unsigned char	s_magic[2];
		__u16		s_state;
		__u32		s_dummy5[8];
		__u32		s_feature_compat;
		__u32		s_feature_incompat;
		__u32		s_feature_ro_compat;
		unsigned char	s_uuid[16];
		char		s_volume_name[16];
	} *es;

	es = (struct ext2_super_block *) (id->buf + EXT_SUPERBLOCK_OFFSET);

	if (es->s_magic[0] != 0123 ||
	    es->s_magic[1] != 0357)
		return -1;

	set_label(id, es->s_volume_name, 16);
	set_uuid(id, es->s_uuid, 16);

	if ((cpu_to_le32(es->s_feature_compat) & EXT3_FEATURE_COMPAT_HAS_JOURNAL) != 0) {
		id->fs_type = EXT3;
		id->fs_name = "ext3";
	} else {
		id->fs_type = EXT2;
		id->fs_name = "ext2";
	}

	return 0;
}

#define REISER1_SUPERBLOCK_OFFSET		0x2000
#define REISER_SUPERBLOCK_OFFSET		0x10000
static int probe_reiser(struct volume_id *id)
{
	struct reiser_super_block {
		__u32		rs_blocks_count;
		__u32		rs_free_blocks;
		__u32		rs_root_block;
		__u32		rs_journal_block;
		__u32		rs_journal_dev;
		__u32		rs_orig_journal_size;
		__u32		rs_dummy2[5];
		__u16		rs_blocksize;
		__u16		rs_dummy3[3];
		unsigned char	rs_magic[12];
		__u32		rs_dummy4[5];
		unsigned char	rs_uuid[16];
		char		rs_label[16];
	} *rs;

	rs = (struct reiser_super_block *) &(id->buf[REISER1_SUPERBLOCK_OFFSET]);

	if (strncmp(rs->rs_magic, "ReIsErFs", 8) == 0)
		goto found;

	rs = (struct reiser_super_block *) &(id->buf[REISER_SUPERBLOCK_OFFSET]);

	if (strncmp(rs->rs_magic, "ReIsEr2Fs", 9) == 0)
		goto found;
	if (strncmp(rs->rs_magic, "ReIsEr3Fs", 9) == 0)
		goto found;

	return -1;

found:
	set_label(id, rs->rs_label, 16);
	set_uuid(id, rs->rs_uuid, 16);

	id->fs_type = REISER;
	id->fs_name = "reiser";

	return 0;
}

static int probe_xfs(struct volume_id *id)
{
	struct xfs_super_block {
		unsigned char	xs_magic[4];
		__u32		xs_blocksize;
		__u64		xs_dblocks;
		__u64		xs_rblocks;
		__u32		xs_dummy1[2];
		unsigned char	xs_uuid[16];
		__u32		xs_dummy2[15];
		char		xs_fname[12];
		__u32		xs_dummy3[2];
		__u64		xs_icount;
		__u64		xs_ifree;
		__u64		xs_fdblocks;
	} *xs;

	xs = (struct xfs_super_block *) id->buf;

	if (strncmp(xs->xs_magic, "XFSB", 4) != 0)
		return -1;

	set_label(id, xs->xs_fname, 12);
	set_uuid(id, xs->xs_uuid, 16);

	id->fs_type = XFS;
	id->fs_name = "xfs";

	return 0;
}

#define JFS_SUPERBLOCK_OFFSET			0x8000
static int probe_jfs(struct volume_id *id)
{
	struct jfs_super_block {
		unsigned char	js_magic[4];
		__u32		js_version;
		__u64		js_size;
		__u32		js_bsize;
		__u32		js_dummy1;
		__u32		js_pbsize;
		__u32		js_dummy2[27];
		unsigned char	js_uuid[16];
		unsigned char	js_label[16];
		unsigned char	js_loguuid[16];
	} *js;

	js = (struct jfs_super_block *) &(id->buf[JFS_SUPERBLOCK_OFFSET]);

	if (strncmp(js->js_magic, "JFS1", 4) != 0)
		return -1;

	set_label(id, js->js_label, 16);
	set_uuid(id, js->js_uuid, 16);

	id->fs_type = JFS;
	id->fs_name = "jfs";

	return 0;
}

static int probe_vfat(struct volume_id *id)
{
	struct vfat_super_block {
		unsigned char	vs_ignored[3];
		unsigned char	vs_sysid[8];
		unsigned char	vs_sector_size[2];
		__u8		vs_cluster_size;
		__u16		vs_reserved;
		__u8		vs_fats;
		unsigned char	vs_dir_entries[2];
		unsigned char	vs_sectors[2];
		unsigned char	vs_media;
		__u16		vs_fat_length;
		__u16		vs_secs_track;
		__u16		vs_heads;
		__u32		vs_hidden;
		__u32		vs_total_sect;
		__u32		vs_fat32_length;
		__u16		vs_flags;
		__u8		vs_version[2];
		__u32		vs_root_cluster;
		__u16		vs_insfo_sector;
		__u16		vs_backup_boot;
		__u16		vs_reserved2[6];
		unsigned char	vs_unknown[3];
		unsigned char	vs_serno[4];
		char		vs_label[11];
		unsigned char	vs_magic[8];
		unsigned char	vs_dummy2[164];
		unsigned char	vs_pmagic[2];
	} *vs;

	vs = (struct vfat_super_block *) id->buf;

	if (strncmp(vs->vs_magic, "MSWIN", 5) == 0)
		goto found;
	if (strncmp(vs->vs_magic, "FAT32   ", 8) == 0)
		goto found;
	return -1;

found:
	memcpy(id->label, vs->vs_label, 11);
	memcpy(id->uuid, vs->vs_serno, 4);

	id->fs_type = VFAT;
	id->fs_name = "vfat";

	return 0;
}

static int probe_msdos(struct volume_id *id)
{
	struct msdos_super_block {
		unsigned char	ms_ignored[3];
		unsigned char	ms_sysid[8];
		unsigned char	ms_sector_size[2];
		__u8		ms_cluster_size;
		__u16		ms_reserved;
		__u8		ms_fats;
		unsigned char	ms_dir_entries[2];
		unsigned char	ms_sectors[2];
		unsigned char	ms_media;
		__u16		ms_fat_length;
		__u16		ms_secs_track;
		__u16		ms_heads;
		__u32		ms_hidden;
		__u32		ms_total_sect;
		unsigned char	ms_unknown[3];
		unsigned char	ms_serno[4];
		char		ms_label[11];
		unsigned char	ms_magic[8];
		unsigned char	ms_dummy2[192];
		unsigned char	ms_pmagic[2];
	} *ms;

	ms = (struct msdos_super_block *) id->buf;

	if (strncmp(ms->ms_magic, "MSDOS", 5) == 0)
		goto found;
	if (strncmp(ms->ms_magic, "FAT16   ", 8) == 0)
		goto found;
	if (strncmp(ms->ms_magic, "FAT12   ", 8) == 0)
		goto found;
	return -1;

found:
	set_label(id, ms->ms_label, 11);
	set_uuid(id, ms->ms_serno, 4);

	id->fs_type = MSDOS;
	id->fs_name = "msdos";

	return 0;
}

static int probe_ntfs(struct volume_id *id)
{
	struct ntfs_super_block {
		char jump[3];
		char oem_id[4];
	} *ns;

	ns = (struct ntfs_super_block *) id->buf;

	if (strncmp(ns->oem_id, "NTFS", 4) != 0)
		return -1;

	id->fs_type = NTFS;
	id->fs_name = "ntfs";

	return 0;
}

static int probe_swap(struct volume_id *id)
{
	int magic;

	/* huhh, the swap signature is on the end of the PAGE_SIZE */
	for (magic = 0x1000; magic <= 0x4000; magic <<= 1) {
			if (strncmp(&(id->buf[magic -10]), "SWAP-SPACE", 10) == 0)
				goto found;
			if (strncmp(&(id->buf[magic -10]), "SWAPSPACE2", 10) == 0)
				goto found;
	}
	return -1;

found:
	id->fs_type = SWAP;
	id->fs_name = "swap";

	return 0;
}

/* probe volume for filesystem type and try to read label+uuid */
int volume_id_probe(struct volume_id *id, enum filesystem_type fs_type)
{
	int rc;

	if (id == NULL)
		return -EINVAL;

	if (open_superblock(id) != 0)
		return -EACCES;

	switch (fs_type) {
	case EXT3:
	case EXT2:
		rc = probe_ext(id);
		break;
	case REISER:
		rc = probe_reiser(id);
		break;
	case XFS:
		rc = probe_xfs(id);
		break;
	case JFS:
		rc = probe_jfs(id);
		break;
	case MSDOS:
		rc = probe_msdos(id);
		break;
	case VFAT:
		rc = probe_vfat(id);
		break;
	case NTFS:
		rc = probe_ntfs(id);
		break;
	case SWAP:
		rc = probe_swap(id);
		break;
	default:
		rc = probe_ext(id);
		if (rc == 0)
			break;
		rc = probe_reiser(id);
		if (rc == 0)
			break;
		rc = probe_xfs(id);
		if (rc == 0)
			break;
		rc = probe_jfs(id);
		if (rc == 0)
			break;
		rc = probe_msdos(id);
		if (rc == 0)
			break;
		rc = probe_vfat(id);
		if (rc == 0)
			break;
		rc = probe_ntfs(id);
		if (rc == 0)
			break;
		rc = probe_swap(id);
		if (rc == 0)
			break;
		rc = -1;
	}

	if (rc == 0)
		close_superblock(id);

	return rc;
}

/* open volume by already open file descriptor */
struct volume_id *volume_id_open_fd(int fd)
{
	struct volume_id *id;

	id = malloc(sizeof(struct volume_id));
	if (id == NULL)
		return NULL;
	memset(id, 0x00, sizeof(struct volume_id));

	id->fd = fd;

	return id;
}

/* open volume by device node */
struct volume_id *volume_id_open_node(const char *path)
{
	struct volume_id *id;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return NULL;

	id = volume_id_open_fd(fd);
	if (id == NULL)
		return NULL;

	/* close fd on device close */
	id->fd_close = 1;

	return id;
}

/* open volume by major/minor */
struct volume_id *volume_id_open_dev_t(dev_t devt)
{
	struct volume_id *id;
	char tmp_node[VOLUME_ID_PATH_MAX];

	snprintf(tmp_node, VOLUME_ID_PATH_MAX,
		 "/tmp/volume-%u-%u", major(devt), minor(devt));
	tmp_node[VOLUME_ID_PATH_MAX] = '\0';

	/* create tempory node to open the block device */
	if (mknod(tmp_node, (S_IFBLK | 0600), devt) != 0)
		return NULL;

	id = volume_id_open_node(tmp_node);

	unlink(tmp_node);

	return id;
}

/* free allocated volume info */
void volume_id_close(struct volume_id *id)
{
	if (id == NULL)
		return;

	if (id->fd_close != 0)
		close(id->fd);

	close_superblock(id);

	free(id);
}
