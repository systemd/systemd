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

#ifdef DEBUG
#define dbg(format, arg...)						\
	do {								\
		printf("%s: " format "\n", __FUNCTION__ , ## arg);	\
	} while (0)
#else
#define dbg(format, arg...)	do {} while (0)
#endif

#define bswap16(x) (__u16)((((__u16)(x) & 0x00ffu) << 8) | \
			   (((__u32)(x) & 0xff00u) >> 8))

#define bswap32(x) (__u32)((((__u32)(x) & 0xff000000u) >> 24) | \
			   (((__u32)(x) & 0x00ff0000u) >>  8) | \
			   (((__u32)(x) & 0x0000ff00u) <<  8) | \
			   (((__u32)(x) & 0x000000ffu) << 24))

#if (__BYTE_ORDER == __LITTLE_ENDIAN) 
#define le16_to_cpu(x) (x)
#define le32_to_cpu(x) (x)
#elif (__BYTE_ORDER == __BIG_ENDIAN)
#define le16_to_cpu(x) bswap16(x)
#define le32_to_cpu(x) bswap32(x)
#endif

/* size of superblock buffer, reiser block is at 64k */
#define SB_BUFFER_SIZE				0x11000
/* size of seek buffer 2k */
#define SEEK_BUFFER_SIZE			0x800


static void set_label_raw(struct volume_id *id, char *buf, int count)
{
	memcpy(id->label_raw, buf, count);
	id->label_raw_len = count;
}

static void set_label_string(struct volume_id *id, char *buf, int count)
{
	int i;

	memcpy(id->label_string, buf, count);

	/* remove trailing whitespace */
	i = strnlen(id->label_string, count);
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
			"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
			"%02x%02x%02x%02x%02x%02x",
			buf[0], buf[1], buf[2], buf[3],
			buf[4], buf[5],
			buf[6], buf[7],
			buf[8], buf[9],
			buf[10], buf[11], buf[12], buf[13], buf[14],buf[15]);
		break;
	}
}

static char *get_buffer(struct volume_id *id, size_t off, size_t len)
{
	size_t buf_len;

	/* check if requested area fits in superblock buffer */
	if (off + len <= SB_BUFFER_SIZE) {
		if (id->sbbuf == NULL) {
			id->sbbuf = malloc(SB_BUFFER_SIZE);
			if (id->sbbuf == NULL)
				return NULL;
		}

		/* check if we need to read */
		if ((off + len) > id->sbbuf_len) {
			dbg("read sbbuf len:0x%x", off + len);
			lseek(id->fd, 0, SEEK_SET);
			buf_len = read(id->fd, id->sbbuf, off + len);
			id->sbbuf_len = buf_len;
			if (buf_len < off + len)
				return NULL;
		}

		return &(id->sbbuf[off]);
	} else {
		if (len > SEEK_BUFFER_SIZE)
			len = SEEK_BUFFER_SIZE;

		/* get seek buffer */
		if (id->seekbuf == NULL) {
			id->seekbuf = malloc(SEEK_BUFFER_SIZE);
			if (id->seekbuf == NULL)
				return NULL;
		}

		/* check if we need to read */
		if ((off < id->seekbuf_off) ||
		    ((off + len) > (id->seekbuf_off + id->seekbuf_len))) {
			dbg("read seekbuf off:0x%x len:0x%x", off, len);
			lseek(id->fd, off, SEEK_SET);
			buf_len = read(id->fd, id->seekbuf, len);
			id->seekbuf_off = off;
			id->seekbuf_len = buf_len;
			if (buf_len < len)
				return NULL;
		}

		return &(id->seekbuf[off - id->seekbuf_off]);
	}
}

static void free_buffer(struct volume_id *id)
{
	if (id->sbbuf != NULL) {
		free(id->sbbuf);
		id->sbbuf = NULL;
		id->sbbuf_len = 0;
	}
	if (id->seekbuf != NULL) {
		free(id->seekbuf);
		id->seekbuf = NULL;
		id->seekbuf_len = 0;
	}
}

#define EXT3_FEATURE_COMPAT_HAS_JOURNAL		0x00000004
#define EXT3_FEATURE_INCOMPAT_JOURNAL_DEV	0x00000008
#define EXT_SUPERBLOCK_OFFSET			0x400
static int probe_ext(struct volume_id *id)
{
	struct ext2_super_block {
		__u32		inodes_count;
		__u32		blocks_count;
		__u32		r_blocks_count;
		__u32		free_blocks_count;
		__u32		free_inodes_count;
		__u32		first_data_block;
		__u32		log_block_size;
		__u32		dummy3[7];
		unsigned char	magic[2];
		__u16		state;
		__u32		dummy5[8];
		__u32		feature_compat;
		__u32		feature_incompat;
		__u32		feature_ro_compat;
		unsigned char	uuid[16];
		char		volume_name[16];
	} *es;

	es = (struct ext2_super_block *)
	     get_buffer(id, EXT_SUPERBLOCK_OFFSET, 0x200);
	if (es == NULL)
		return -1;

	if (es->magic[0] != 0123 ||
	    es->magic[1] != 0357)
		return -1;

	set_label_raw(id, es->volume_name, 16);
	set_label_string(id, es->volume_name, 16);
	set_uuid(id, es->uuid, 16);

	if ((le32_to_cpu(es->feature_compat) &
	     EXT3_FEATURE_COMPAT_HAS_JOURNAL) != 0) {
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
		__u32		blocks_count;
		__u32		free_blocks;
		__u32		root_block;
		__u32		journal_block;
		__u32		journal_dev;
		__u32		orig_journal_size;
		__u32		dummy2[5];
		__u16		blocksize;
		__u16		dummy3[3];
		unsigned char	magic[12];
		__u32		dummy4[5];
		unsigned char	uuid[16];
		char		label[16];
	} *rs;

	rs = (struct reiser_super_block *)
	     get_buffer(id, REISER_SUPERBLOCK_OFFSET, 0x200);
	if (rs == NULL)
		return -1;

	if (strncmp(rs->magic, "ReIsEr2Fs", 9) == 0)
		goto found;
	if (strncmp(rs->magic, "ReIsEr3Fs", 9) == 0)
		goto found;

	rs = (struct reiser_super_block *)
	     get_buffer(id, REISER1_SUPERBLOCK_OFFSET, 0x200);
	if (rs == NULL)
		return -1;

	if (strncmp(rs->magic, "ReIsErFs", 8) == 0)
		goto found;

	return -1;

found:
	set_label_raw(id, rs->label, 16);
	set_label_string(id, rs->label, 16);
	set_uuid(id, rs->uuid, 16);

	id->fs_type = REISER;
	id->fs_name = "reiser";

	return 0;
}

static int probe_xfs(struct volume_id *id)
{
	struct xfs_super_block {
		unsigned char	magic[4];
		__u32		blocksize;
		__u64		dblocks;
		__u64		rblocks;
		__u32		dummy1[2];
		unsigned char	uuid[16];
		__u32		dummy2[15];
		char		fname[12];
		__u32		dummy3[2];
		__u64		icount;
		__u64		ifree;
		__u64		fdblocks;
	} *xs;

	xs = (struct xfs_super_block *) get_buffer(id, 0, 0x200);
	if (xs == NULL)
		return -1;

	if (strncmp(xs->magic, "XFSB", 4) != 0)
		return -1;

	set_label_raw(id, xs->fname, 12);
	set_label_string(id, xs->fname, 12);
	set_uuid(id, xs->uuid, 16);

	id->fs_type = XFS;
	id->fs_name = "xfs";

	return 0;
}

#define JFS_SUPERBLOCK_OFFSET			0x8000
static int probe_jfs(struct volume_id *id)
{
	struct jfs_super_block {
		unsigned char	magic[4];
		__u32		version;
		__u64		size;
		__u32		bsize;
		__u32		dummy1;
		__u32		pbsize;
		__u32		dummy2[27];
		unsigned char	uuid[16];
		unsigned char	label[16];
		unsigned char	loguuid[16];
	} *js;

	js = (struct jfs_super_block *)
	     get_buffer(id, JFS_SUPERBLOCK_OFFSET, 0x200);
	if (js == NULL)
		return -1;

	if (strncmp(js->magic, "JFS1", 4) != 0)
		return -1;

	set_label_raw(id, js->label, 16);
	set_label_string(id, js->label, 16);
	set_uuid(id, js->uuid, 16);

	id->fs_type = JFS;
	id->fs_name = "jfs";

	return 0;
}

static int probe_vfat(struct volume_id *id)
{
	struct vfat_super_block {
		unsigned char	ignored[3];
		unsigned char	sysid[8];
		unsigned char	sector_size[2];
		__u8		cluster_size;
		__u16		reserved;
		__u8		fats;
		unsigned char	dir_entries[2];
		unsigned char	sectors[2];
		unsigned char	media;
		__u16		fat_length;
		__u16		secs_track;
		__u16		heads;
		__u32		hidden;
		__u32		total_sect;
		__u32		fat32_length;
		__u16		flags;
		__u8		version[2];
		__u32		root_cluster;
		__u16		insfo_sector;
		__u16		backup_boot;
		__u16		reserved2[6];
		unsigned char	unknown[3];
		unsigned char	serno[4];
		char		label[11];
		unsigned char	magic[8];
		unsigned char	dummy2[164];
		unsigned char	pmagic[2];
	} *vs;

	vs = (struct vfat_super_block *) get_buffer(id, 0, 0x200);
	if (vs == NULL)
		return -1;

	if (strncmp(vs->magic, "MSWIN", 5) == 0)
		goto found;
	if (strncmp(vs->magic, "FAT32   ", 8) == 0)
		goto found;
	return -1;

found:
	set_label_raw(id, vs->label, 11);
	set_label_string(id, vs->label, 11);
	set_uuid(id, vs->serno, 4);

	id->fs_type = VFAT;
	id->fs_name = "vfat";

	return 0;
}

static int probe_msdos(struct volume_id *id)
{
	struct msdos_super_block {
		unsigned char	ignored[3];
		unsigned char	sysid[8];
		unsigned char	sector_size[2];
		__u8		cluster_size;
		__u16		reserved;
		__u8		fats;
		unsigned char	dir_entries[2];
		unsigned char	sectors[2];
		unsigned char	media;
		__u16		fat_length;
		__u16		secs_track;
		__u16		heads;
		__u32		hidden;
		__u32		total_sect;
		unsigned char	unknown[3];
		unsigned char	serno[4];
		char		label[11];
		unsigned char	magic[8];
		unsigned char	dummy2[192];
		unsigned char	pmagic[2];
	} *ms;

	ms = (struct msdos_super_block *) get_buffer(id, 0, 0x200);
	if (ms == NULL)
		return -1;

	if (strncmp(ms->magic, "MSDOS", 5) == 0)
		goto found;
	if (strncmp(ms->magic, "FAT16   ", 8) == 0)
		goto found;
	if (strncmp(ms->magic, "FAT12   ", 8) == 0)
		goto found;
	return -1;

found:
	set_label_raw(id, ms->label, 11);
	set_label_string(id, ms->label, 11);
	set_uuid(id, ms->serno, 4);

	id->fs_type = MSDOS;
	id->fs_name = "msdos";

	return 0;
}

#define UDF_VSD_OFFSET			0x8000
static int probe_udf(struct volume_id *id)
{
	struct volume_descriptor {
		struct descriptor_tag {
			__u16		id;
			__u16		version;
			unsigned char	checksum;
			unsigned char	reserved;
			__u16		serial;
			__u16		crc;
			__u16		crc_len;
			__u32		location;
		} tag;
		union {
			struct anchor_descriptor {
				__u32		length;
				__u32		location;
			} anchor;
			struct primary_descriptor {
				__u32		seq_num;
				__u32		desc_num;
				struct dstring {
					char		clen;
					char		c[31];
				} ident;
			} primary;
		} type;
	} *vd;

	struct volume_structure_descriptor {
		unsigned char	type;
		char		id[5];
		unsigned char	version;
	} *vsd;

	size_t bs;
	size_t b;
	int type;
	int count;
	int loc;
	int clen;
	int i,j;
	int c;

	vsd = (struct volume_structure_descriptor *)
	      get_buffer(id, UDF_VSD_OFFSET, 0x200);
	if (vsd == NULL)
		return -1;

	if (strncmp(vsd->id, "NSR02", 5) == 0)
		goto blocksize;
	if (strncmp(vsd->id, "NSR03", 5) == 0)
		goto blocksize;
	if (strncmp(vsd->id, "BEA01", 5) == 0)
		goto blocksize;
	if (strncmp(vsd->id, "BOOT2", 5) == 0)
		goto blocksize;
	if (strncmp(vsd->id, "CD001", 5) == 0)
		goto blocksize;
	if (strncmp(vsd->id, "CDW02", 5) == 0)
		goto blocksize;
	if (strncmp(vsd->id, "TEA03", 5) == 0)
		goto blocksize;
	return -1;

blocksize:
	/* search the next VSD to get the logical block size of the volume */
	for (bs = 0x800; bs < 0x8000; bs += 0x800) {
		vsd = (struct volume_structure_descriptor *)
		      get_buffer(id, UDF_VSD_OFFSET + bs, 0x800);
		if (vsd == NULL)
			return -1;
		dbg("test for blocksize: 0x%x", bs);
		if (vsd->id[0] != '\0')
			goto nsr;
	}
	return -1;

nsr:
	/* search the list of VSDs for a NSR descriptor */
	for (b = 0; b < 64; b++) {
		vsd = (struct volume_structure_descriptor *)
		      get_buffer(id, UDF_VSD_OFFSET + (b * bs), 0x800);
		if (vsd == NULL)
			return -1;

		dbg("vsd: %c%c%c%c%c",
		    vsd->id[0], vsd->id[1], vsd->id[2], vsd->id[3], vsd->id[4]);

		if (vsd->id[0] == '\0')
			return -1;
		if (strncmp(vsd->id, "NSR02", 5) == 0)
			goto anchor;
		if (strncmp(vsd->id, "NSR03", 5) == 0)
			goto anchor;
	}
	return -1;

anchor:
	/* read anchor volume descriptor */
	vd = (struct volume_descriptor *) get_buffer(id, 256 * bs, 0x200);
	if (vd == NULL)
		return -1;

	type = le16_to_cpu(vd->tag.id);
	if (type != 2) /* TAG_ID_AVDP */
		goto found;

	/* get desriptor list address and block count */
	count = le32_to_cpu(vd->type.anchor.length) / bs;
	loc = le32_to_cpu(vd->type.anchor.location);
	dbg("0x%x descriptors starting at logical secor 0x%x", count, loc);

	/* pick the primary descriptor from the list */
	for (b = 0; b < count; b++) {
		vd = (struct volume_descriptor *)
		     get_buffer(id, (loc + b) * bs, 0x200);
		if (vd == NULL)
			return -1;

		type = le16_to_cpu(vd->tag.id);
		dbg("descriptor type %i", type);

		/* check validity */
		if (type == 0)
			goto found;
		if (le32_to_cpu(vd->tag.location) != loc + b)
			goto found;

		if (type == 1) /* TAG_ID_PVD */
			goto pvd;
	}
	goto found;

pvd:
	set_label_raw(id, &(vd->type.primary.ident.clen), 32);

	clen = vd->type.primary.ident.clen;
	dbg("label string charsize=%i bit", clen);
	if (clen == 8) {
		set_label_string(id, vd->type.primary.ident.c, 31);
	} else if (clen == 16) {
		/* convert unicode OSTA dstring to UTF-8 */
		j = 0;
		for (i = 0; i < 32; i += 2) {
			c = (vd->type.primary.ident.c[i] << 8) |
			    vd->type.primary.ident.c[i+1];
			if (c == 0) {
				id->label_string[j] = '\0';
				break;
			}else if (c < 0x80U) {
				id->label_string[j++] = (char) c;
			} else if (c < 0x800U) {
				id->label_string[j++] = (char) (0xc0 | (c >> 6));
				id->label_string[j++] = (char) (0x80 | (c & 0x3f));
			} else {
				id->label_string[j++] = (char) (0xe0 | (c >> 12));
				id->label_string[j++] = (char) (0x80 | ((c >> 6) & 0x3f));
				id->label_string[j++] = (char) (0x80 | (c & 0x3f));
			}
		}
	}

found:
	id->fs_type = UDF;
	id->fs_name = "udf";

	return 0;
}

#define ISO_SUPERBLOCK_OFFSET		0x8000
static int probe_iso9660(struct volume_id *id)
{
	union iso_super_block {
		struct iso_header {
			unsigned char	type;
			char		id[5];
			unsigned char	version;
			unsigned char	unused1;
			char		system_id[32];
			char		volume_id[32];
		} iso;
		struct hs_header {
			char		foo[8];
			unsigned char	type;
			char		id[4];
			unsigned char	version;
		} hs;
	} *is;

	is = (union iso_super_block *)
	     get_buffer(id, ISO_SUPERBLOCK_OFFSET, 0x200);
	if (is == NULL)
		return -1;

	if (strncmp(is->iso.id, "CD001", 5) == 0) {
		set_label_raw(id, is->iso.volume_id, 32);
		set_label_string(id, is->iso.volume_id, 32);
		goto found;
	}
	if (strncmp(is->hs.id, "CDROM", 5) == 0)
		goto found;
	return -1;

found:
	id->fs_type = ISO9660;
	id->fs_name = "iso9660";

	return 0;
}

static int probe_ntfs(struct volume_id *id)
{
	struct ntfs_super_block {
		char jump[3];
		char oem_id[4];
	} *ns;

	ns = (struct ntfs_super_block *) get_buffer(id, 0, 0x200);
	if (ns == NULL)
		return -1;

	if (strncmp(ns->oem_id, "NTFS", 4) != 0)
		return -1;

	id->fs_type = NTFS;
	id->fs_name = "ntfs";

	return 0;
}

#define LARGEST_PAGESIZE			0x4000
static int probe_swap(struct volume_id *id)
{
	char *sig;
	size_t page;

	/* huhh, the swap signature is on the end of the PAGE_SIZE */
	for (page = 0x1000; page <= LARGEST_PAGESIZE; page <<= 1) {
			sig = get_buffer(id, page-10, 10);
			if (sig == NULL)
				return -1;

			if (strncmp(sig, "SWAP-SPACE", 10) == 0)
				goto found;
			if (strncmp(sig, "SWAPSPACE2", 10) == 0)
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
	case UDF:
		rc = probe_udf(id);
		break;
	case ISO9660:
		rc = probe_iso9660(id);
		break;
	case NTFS:
		rc = probe_ntfs(id);
		break;
	case SWAP:
		rc = probe_swap(id);
		break;
	case ALL:
	default:
		/* fill buffer with maximum */
		get_buffer(id, 0, SB_BUFFER_SIZE);
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
		rc = probe_udf(id);
		if (rc == 0)
			break;
		rc = probe_iso9660(id);
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

	/* If the filestystem in recognized, we free the allocated buffers,
	   otherwise they will stay in place for the possible next probe call */
	if (rc == 0)
		free_buffer(id);

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
		 "/tmp/volume-%u-%u-%u", getpid(), major(devt), minor(devt));
	tmp_node[VOLUME_ID_PATH_MAX] = '\0';

	/* create tempory node to open the block device */
	unlink(tmp_node);
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

	free_buffer(id);

	free(id);
}
