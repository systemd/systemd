/*
 * volume_id - reads filesystem label and uuid
 *
 * Copyright (C) 2004 Kay Sievers <kay.sievers@vrfy.org>
 *
 *	The superblock structs are taken from the linux kernel sources
 *	and the libblkid living inside the e2fsprogs. This is a simple
 *	straightforward implementation for reading the label strings of the
 *	most common filesystems.
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
#include <fcntl.h>
#include <sys/stat.h>
#include <asm/types.h>

#include "volume_id.h"
#include "volume_id_logging.h"

#define bswap16(x) (__u16)((((__u16)(x) & 0x00ffu) << 8) | \
			   (((__u16)(x) & 0xff00u) >> 8))

#define bswap32(x) (__u32)((((__u32)(x) & 0xff000000u) >> 24) | \
			   (((__u32)(x) & 0x00ff0000u) >>  8) | \
			   (((__u32)(x) & 0x0000ff00u) <<  8) | \
			   (((__u32)(x) & 0x000000ffu) << 24))

#define bswap64(x) (__u64)((((__u64)(x) & 0xff00000000000000ull) >> 56) | \
			   (((__u64)(x) & 0x00ff000000000000ull) >> 40) | \
			   (((__u64)(x) & 0x0000ff0000000000ull) >> 24) | \
			   (((__u64)(x) & 0x000000ff00000000ull) >>  8) | \
			   (((__u64)(x) & 0x00000000ff000000ull) <<  8) | \
			   (((__u64)(x) & 0x0000000000ff0000ull) << 24) | \
			   (((__u64)(x) & 0x000000000000ff00ull) << 40) | \
			   (((__u64)(x) & 0x00000000000000ffull) << 56))

#if (__BYTE_ORDER == __LITTLE_ENDIAN)
#define le16_to_cpu(x) (x)
#define le32_to_cpu(x) (x)
#define le64_to_cpu(x) (x)
#define be16_to_cpu(x) bswap16(x)
#define be32_to_cpu(x) bswap32(x)
#elif (__BYTE_ORDER == __BIG_ENDIAN)
#define le16_to_cpu(x) bswap16(x)
#define le32_to_cpu(x) bswap32(x)
#define le64_to_cpu(x) bswap64(x)
#define be16_to_cpu(x) (x)
#define be32_to_cpu(x) (x)
#endif

/* size of superblock buffer, reiserfs block is at 64k */
#define SB_BUFFER_SIZE				0x11000
/* size of seek buffer 4k */
#define SEEK_BUFFER_SIZE			0x10000


static void set_label_raw(struct volume_id *id,
			  const __u8 *buf, unsigned int count)
{
	memcpy(id->label_raw, buf, count);
	id->label_raw_len = count;
}

static void set_label_string(struct volume_id *id,
			     const __u8 *buf, unsigned int count)
{
	unsigned int i;

	memcpy(id->label, buf, count);

	/* remove trailing whitespace */
	i = strnlen(id->label, count);
	while (i--) {
		if (! isspace(id->label[i]))
			break;
	}
	id->label[i+1] = '\0';
}

#define LE		0
#define BE		1
static void set_label_unicode16(struct volume_id *id,
				const __u8 *buf,
				unsigned int endianess,
				unsigned int count)
{
	unsigned int i, j;
	__u16 c;

	j = 0;
	for (i = 0; i + 2 <= count; i += 2) {
		if (endianess == LE)
			c = (buf[i+1] << 8) | buf[i];
		else
			c = (buf[i] << 8) | buf[i+1];
		if (c == 0) {
			id->label[j] = '\0';
			break;
		} else if (c < 0x80) {
			id->label[j++] = (__u8) c;
		} else if (c < 0x800) {
			id->label[j++] = (__u8) (0xc0 | (c >> 6));
			id->label[j++] = (__u8) (0x80 | (c & 0x3f));
		} else {
			id->label[j++] = (__u8) (0xe0 | (c >> 12));
			id->label[j++] = (__u8) (0x80 | ((c >> 6) & 0x3f));
			id->label[j++] = (__u8) (0x80 | (c & 0x3f));
		}
	}
}

enum uuid_format {
	UUID_DCE,
	UUID_DOS,
	UUID_NTFS,
	UUID_HFS,
};

static void set_uuid(struct volume_id *id, const __u8 *buf, enum uuid_format format)
{
	unsigned int i;
	unsigned int count = 0;

	switch(format) {
	case UUID_DOS:
		count = 4;
		break;
	case UUID_NTFS:
	case UUID_HFS:
		count = 8;
		break;
	case UUID_DCE:
		count = 16;
	}
	memcpy(id->uuid_raw, buf, count);

	/* if set, create string in the same format, the native platform uses */
	for (i = 0; i < count; i++)
		if (buf[i] != 0)
			goto set;
	return;

set:
	switch(format) {
	case UUID_DOS:
		sprintf(id->uuid, "%02X%02X-%02X%02X",
			buf[3], buf[2], buf[1], buf[0]);
		break;
	case UUID_NTFS:
		sprintf(id->uuid,"%02X%02X%02X%02X%02X%02X%02X%02X",
			buf[7], buf[6], buf[5], buf[4],
			buf[3], buf[2], buf[1], buf[0]);
		break;
	case UUID_HFS:
		sprintf(id->uuid,"%02X%02X%02X%02X%02X%02X%02X%02X",
			buf[0], buf[1], buf[2], buf[3],
			buf[4], buf[5], buf[6], buf[7]);
		break;
	case UUID_DCE:
		sprintf(id->uuid,
			"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
			buf[0], buf[1], buf[2], buf[3],
			buf[4], buf[5],
			buf[6], buf[7],
			buf[8], buf[9],
			buf[10], buf[11], buf[12], buf[13], buf[14],buf[15]);
		break;
	}
}

static __u8 *get_buffer(struct volume_id *id, __u64 off, unsigned int len)
{
	unsigned int buf_len;

	dbg("get buffer off 0x%llx, len 0x%x", off, len);
	/* check if requested area fits in superblock buffer */
	if (off + len <= SB_BUFFER_SIZE) {
		if (id->sbbuf == NULL) {
			id->sbbuf = malloc(SB_BUFFER_SIZE);
			if (id->sbbuf == NULL)
				return NULL;
		}

		/* check if we need to read */
		if ((off + len) > id->sbbuf_len) {
			dbg("read sbbuf len:0x%llx", off + len);
			lseek(id->fd, 0, SEEK_SET);
			buf_len = read(id->fd, id->sbbuf, off + len);
			dbg("got 0x%x (%i) bytes", buf_len, buf_len);
			id->sbbuf_len = buf_len;
			if (buf_len < off + len)
				return NULL;
		}

		return &(id->sbbuf[off]);
	} else {
		if (len > SEEK_BUFFER_SIZE) {
			dbg("seek buffer too small %d", SEEK_BUFFER_SIZE);
			return NULL;
		}

		/* get seek buffer */
		if (id->seekbuf == NULL) {
			id->seekbuf = malloc(SEEK_BUFFER_SIZE);
			if (id->seekbuf == NULL)
				return NULL;
		}

		/* check if we need to read */
		if ((off < id->seekbuf_off) || ((off + len) > (id->seekbuf_off + id->seekbuf_len))) {
			dbg("read seekbuf off:0x%llx len:0x%x", off, len);
			if (lseek(id->fd, off, SEEK_SET) == -1)
				return NULL;
			buf_len = read(id->fd, id->seekbuf, len);
			dbg("got 0x%x (%i) bytes", buf_len, buf_len);
			id->seekbuf_off = off;
			id->seekbuf_len = buf_len;
			if (buf_len < len) {
				dbg("requested 0x%x bytes, got only 0x%x bytes", len, buf_len);
				return NULL;
			}
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

#define HPT37X_CONFIG_OFF		0x1200
#define HPT37X_MAGIC_OK			0x5a7816f0
#define HPT37X_MAGIC_BAD		0x5a7816fd
static int probe_highpoint_ataraid(struct volume_id *id, __u64 off)
{
	struct hpt37x {
		__u8	filler1[32];
		__u32	magic;
		__u32	magic_0;
		__u32	magic_1;
	} __attribute__((packed)) *hpt;

	const __u8 *buf;

	buf = get_buffer(id, off + HPT37X_CONFIG_OFF, 0x200);
	if (buf == NULL)
		return -1;

	hpt = (struct hpt37x *) buf;

	if (hpt->magic != HPT37X_MAGIC_OK && hpt->magic != HPT37X_MAGIC_BAD)
		return -1;

	id->usage_id = VOLUME_ID_RAID;
	id->type_id = VOLUME_ID_HPTRAID;
	id->type = "hpt_ataraid_member";

	return 0;
}

#define LVM1_SB_OFF			0x400
#define LVM1_MAGIC			"HM"
static int probe_lvm1(struct volume_id *id, __u64 off)
{
	struct lvm2_super_block {
		__u8	id[2];
	} __attribute__((packed)) *lvm;

	const __u8 *buf;

	buf = get_buffer(id, off + LVM1_SB_OFF, 0x800);
	if (buf == NULL)
		return -1;

	lvm = (struct lvm2_super_block *) buf;

	if (strncmp(lvm->id, LVM1_MAGIC, 2) != 0)
		return -1;

	id->usage_id = VOLUME_ID_RAID;
	id->type_id = VOLUME_ID_LVM1;
	id->type = "LVM1_member";

	return 0;
}

#define LVM2_LABEL_ID			"LABELONE"
#define LVM2LABEL_SCAN_SECTORS		4
static int probe_lvm2(struct volume_id *id, __u64 off)
{
	struct lvm2_super_block {
		__u8	id[8];
		__u64	sector_xl;
		__u32	crc_xl;
		__u32	offset_xl;
		__u8	type[8];
	} __attribute__((packed)) *lvm;

	const __u8 *buf;
	unsigned int soff;

	buf = get_buffer(id, off, LVM2LABEL_SCAN_SECTORS * 0x200);
	if (buf == NULL)
		return -1;


	for (soff = 0; soff < LVM2LABEL_SCAN_SECTORS * 0x200; soff += 0x200) {
		lvm = (struct lvm2_super_block *) &buf[soff];

		if (strncmp(lvm->id, LVM2_LABEL_ID, 8) == 0)
			goto found;
	}

	return -1;

found:
	strncpy(id->type_version, lvm->type, 8);
	id->usage_id = VOLUME_ID_RAID;
	id->type_id = VOLUME_ID_LVM2;
	id->type = "LVM2_member";

	return 0;
}

#define MD_RESERVED_BYTES		0x10000
#define MD_MAGIC			0xa92b4efc
static int probe_linux_raid(struct volume_id *id, __u64 off, __u64 size)
{
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

	const __u8 *buf;
	__u64 sboff;
	__u8 uuid[16];

	if (size < 0x10000)
		return -1;

	sboff = (size & ~(MD_RESERVED_BYTES - 1)) - MD_RESERVED_BYTES;
	buf = get_buffer(id, off + sboff, 0x800);
	if (buf == NULL)
		return -1;

	mdp = (struct mdp_super_block *) buf;

	if (le32_to_cpu(mdp->md_magic) != MD_MAGIC)
		return -1;

	memcpy(uuid, &mdp->set_uuid0, 4);
	memcpy(&uuid[4], &mdp->set_uuid1, 12);
	set_uuid(id, uuid, UUID_DCE);

	snprintf(id->type_version, VOLUME_ID_FORMAT_SIZE-1, "%u.%u.%u",
		 le32_to_cpu(mdp->major_version),
		 le32_to_cpu(mdp->minor_version),
		 le32_to_cpu(mdp->patch_version));

	dbg("found raid signature");
	id->usage_id = VOLUME_ID_RAID;
	id->type = "linux_raid_member";

	return 0;
}

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
static int probe_msdos_part_table(struct volume_id *id, __u64 off)
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

	buf = get_buffer(id, off, 0x200);
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
			p->usage_id = VOLUME_ID_PARTITIONTABLE;
			p->type_id = VOLUME_ID_MSDOSEXTENDED;
			p->type = "msdos_extended_partition";
			if (extended == 0)
				extended = off + poff;
		} else {
			dbg("found 0x%x data partition at 0x%llx, len 0x%llx",
			    part[i].sys_ind, poff, plen);

			if (is_raid(part[i].sys_ind))
				p->usage_id = VOLUME_ID_RAID;
			else
				p->usage_id = VOLUME_ID_UNPROBED;
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

		buf = get_buffer(id, current, 0x200);
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
					id->partitions[id->partition_count++].usage_id =
						VOLUME_ID_UNUSED;

				p = &id->partitions[id->partition_count];

				if (is_raid(part[i].sys_ind))
					p->usage_id = VOLUME_ID_RAID;
				else
					p->usage_id = VOLUME_ID_UNPROBED;

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

	id->usage_id = VOLUME_ID_PARTITIONTABLE;
	id->type_id = VOLUME_ID_MSDOSPARTTABLE;
	id->type = "msdos_partition_table";

	return 0;
}

#define EXT3_FEATURE_COMPAT_HAS_JOURNAL		0x00000004
#define EXT3_FEATURE_INCOMPAT_JOURNAL_DEV	0x00000008
#define EXT_SUPERBLOCK_OFFSET			0x400
static int probe_ext(struct volume_id *id, __u64 off)
{
	struct ext2_super_block {
		__u32	inodes_count;
		__u32	blocks_count;
		__u32	r_blocks_count;
		__u32	free_blocks_count;
		__u32	free_inodes_count;
		__u32	first_data_block;
		__u32	log_block_size;
		__u32	dummy3[7];
		__u8	magic[2];
		__u16	state;
		__u32	dummy5[8];
		__u32	feature_compat;
		__u32	feature_incompat;
		__u32	feature_ro_compat;
		__u8	uuid[16];
		__u8	volume_name[16];
	} __attribute__((__packed__)) *es;

	es = (struct ext2_super_block *)
	     get_buffer(id, off + EXT_SUPERBLOCK_OFFSET, 0x200);
	if (es == NULL)
		return -1;

	if (es->magic[0] != 0123 ||
	    es->magic[1] != 0357)
		return -1;

	set_label_raw(id, es->volume_name, 16);
	set_label_string(id, es->volume_name, 16);
	set_uuid(id, es->uuid, UUID_DCE);

	if ((le32_to_cpu(es->feature_compat) &
	     EXT3_FEATURE_COMPAT_HAS_JOURNAL) != 0) {
		id->usage_id = VOLUME_ID_FILESYSTEM;
		id->type_id = VOLUME_ID_EXT3;
		id->type = "ext3";
	} else {
		id->usage_id = VOLUME_ID_FILESYSTEM;
		id->type_id = VOLUME_ID_EXT2;
		id->type = "ext2";
	}

	return 0;
}

#define REISERFS1_SUPERBLOCK_OFFSET		0x2000
#define REISERFS_SUPERBLOCK_OFFSET		0x10000
static int probe_reiserfs(struct volume_id *id, __u64 off)
{
	struct reiserfs_super_block {
		__u32	blocks_count;
		__u32	free_blocks;
		__u32	root_block;
		__u32	journal_block;
		__u32	journal_dev;
		__u32	orig_journal_size;
		__u32	dummy2[5];
		__u16	blocksize;
		__u16	dummy3[3];
		__u8	magic[12];
		__u32	dummy4[5];
		__u8	uuid[16];
		__u8	label[16];
	} __attribute__((__packed__)) *rs;

	rs = (struct reiserfs_super_block *)
	     get_buffer(id, off + REISERFS_SUPERBLOCK_OFFSET, 0x200);
	if (rs == NULL)
		return -1;

	if (strncmp(rs->magic, "ReIsEr2Fs", 9) == 0) {
		strcpy(id->type_version, "3.6");
		goto found;
	}

	if (strncmp(rs->magic, "ReIsEr3Fs", 9) == 0) {
		strcpy(id->type_version, "JR");
		goto found;
	}

	rs = (struct reiserfs_super_block *)
	     get_buffer(id, off + REISERFS1_SUPERBLOCK_OFFSET, 0x200);
	if (rs == NULL)
		return -1;

	if (strncmp(rs->magic, "ReIsErFs", 8) == 0) {
		strcpy(id->type_version, "3.5");
		goto found;
	}

	return -1;

found:
	set_label_raw(id, rs->label, 16);
	set_label_string(id, rs->label, 16);
	set_uuid(id, rs->uuid, UUID_DCE);

	id->usage_id = VOLUME_ID_FILESYSTEM;
	id->type_id = VOLUME_ID_REISERFS;
	id->type = "reiserfs";

	return 0;
}

static int probe_xfs(struct volume_id *id, __u64 off)
{
	struct xfs_super_block {
		__u8	magic[4];
		__u32	blocksize;
		__u64	dblocks;
		__u64	rblocks;
		__u32	dummy1[2];
		__u8	uuid[16];
		__u32	dummy2[15];
		__u8	fname[12];
		__u32	dummy3[2];
		__u64	icount;
		__u64	ifree;
		__u64	fdblocks;
	} __attribute__((__packed__)) *xs;

	xs = (struct xfs_super_block *) get_buffer(id, off, 0x200);
	if (xs == NULL)
		return -1;

	if (strncmp(xs->magic, "XFSB", 4) != 0)
		return -1;

	set_label_raw(id, xs->fname, 12);
	set_label_string(id, xs->fname, 12);
	set_uuid(id, xs->uuid, UUID_DCE);

	id->usage_id = VOLUME_ID_FILESYSTEM;
	id->type_id = VOLUME_ID_XFS;
	id->type = "xfs";

	return 0;
}

#define JFS_SUPERBLOCK_OFFSET			0x8000
static int probe_jfs(struct volume_id *id, __u64 off)
{
	struct jfs_super_block {
		__u8	magic[4];
		__u32	version;
		__u64	size;
		__u32	bsize;
		__u32	dummy1;
		__u32	pbsize;
		__u32	dummy2[27];
		__u8	uuid[16];
		__u8	label[16];
		__u8	loguuid[16];
	} __attribute__((__packed__)) *js;

	js = (struct jfs_super_block *)
	     get_buffer(id, off + JFS_SUPERBLOCK_OFFSET, 0x200);
	if (js == NULL)
		return -1;

	if (strncmp(js->magic, "JFS1", 4) != 0)
		return -1;

	set_label_raw(id, js->label, 16);
	set_label_string(id, js->label, 16);
	set_uuid(id, js->uuid, UUID_DCE);

	id->usage_id = VOLUME_ID_FILESYSTEM;
	id->type_id = VOLUME_ID_JFS;
	id->type = "jfs";

	return 0;
}

#define FAT12_MAX			0xff5
#define FAT16_MAX			0xfff5
#define FAT_ATTR_VOLUME_ID		0x08
#define FAT_ATTR_DIR			0x10
#define FAT_ATTR_LONG_NAME		0x0f
#define FAT_ATTR_MASK			0x3f
#define FAT_ENTRY_FREE			0xe5
static int probe_vfat(struct volume_id *id, __u64 off)
{
	struct vfat_super_block {
		__u8	boot_jump[3];
		__u8	sysid[8];
		__u16	sector_size;
		__u8	sectors_per_cluster;
		__u16	reserved;
		__u8	fats;
		__u16	dir_entries;
		__u16	sectors;
		__u8	media;
		__u16	fat_length;
		__u16	secs_track;
		__u16	heads;
		__u32	hidden;
		__u32	total_sect;
		union {
			struct fat_super_block {
				__u8	unknown[3];
				__u8	serno[4];
				__u8	label[11];
				__u8	magic[8];
				__u8	dummy2[192];
				__u8	pmagic[2];
			} __attribute__((__packed__)) fat;
			struct fat32_super_block {
				__u32	fat32_length;
				__u16	flags;
				__u8	version[2];
				__u32	root_cluster;
				__u16	insfo_sector;
				__u16	backup_boot;
				__u16	reserved2[6];
				__u8	unknown[3];
				__u8	serno[4];
				__u8	label[11];
				__u8	magic[8];
				__u8	dummy2[164];
				__u8	pmagic[2];
			} __attribute__((__packed__)) fat32;
		} __attribute__((__packed__)) type;
	} __attribute__((__packed__)) *vs;

	struct vfat_dir_entry {
		__u8	name[11];
		__u8	attr;
		__u16	time_creat;
		__u16	date_creat;
		__u16	time_acc;
		__u16	date_acc;
		__u16	cluster_high;
		__u16	time_write;
		__u16	date_write;
		__u16	cluster_low;
		__u32	size;
	} __attribute__((__packed__)) *dir;

	__u16 sector_size;
	__u16 dir_entries;
	__u32 sect_count;
	__u16 reserved;
	__u32 fat_size;
	__u32 root_cluster;
	__u32 dir_size;
	__u32 cluster_count;
	__u32 fat_length;
	__u64 root_start;
	__u32 start_data_sect;
	__u16 root_dir_entries;
	__u8 *buf;
	__u32 buf_size;
	__u8 *label = NULL;
	__u32 next;
	int maxloop;
	int i;

	vs = (struct vfat_super_block *) get_buffer(id, off, 0x200);
	if (vs == NULL)
		return -1;

	/* believe only that's fat, don't trust the version
	 * the cluster_count will tell us
	 */
	if (strncmp(vs->sysid, "NTFS", 4) == 0)
		return -1;

	if (strncmp(vs->type.fat32.magic, "MSWIN", 5) == 0)
		goto valid;

	if (strncmp(vs->type.fat32.magic, "FAT32   ", 8) == 0)
		goto valid;

	if (strncmp(vs->type.fat.magic, "FAT16   ", 8) == 0)
		goto valid;

	if (strncmp(vs->type.fat.magic, "MSDOS", 5) == 0)
		goto valid;

	if (strncmp(vs->type.fat.magic, "FAT12   ", 8) == 0)
		goto valid;

	/*
	 * There are old floppies out there without a magic, so we check
	 * for well known values and guess if it's a fat volume
	 */

	/* boot jump address check */
	if ((vs->boot_jump[0] != 0xeb || vs->boot_jump[2] != 0x90) &&
	     vs->boot_jump[0] != 0xe9)
		return -1;

	/* heads check */
	if (vs->heads == 0)
		return -1;

	/* cluster size check*/	
	if (vs->sectors_per_cluster == 0 ||
	    (vs->sectors_per_cluster & (vs->sectors_per_cluster-1)))
		return -1;

	/* media check */
	if (vs->media < 0xf8 && vs->media != 0xf0)
		return -1;

	/* fat count*/
	if (vs->fats != 2)
		return -1;

valid:
	/* sector size check */
	sector_size = le16_to_cpu(vs->sector_size);
	if (sector_size != 0x200 && sector_size != 0x400 &&
	    sector_size != 0x800 && sector_size != 0x1000)
		return -1;

	dbg("sector_size 0x%x", sector_size);
	dbg("sectors_per_cluster 0x%x", vs->sectors_per_cluster);

	dir_entries = le16_to_cpu(vs->dir_entries);
	reserved = le16_to_cpu(vs->reserved);
	dbg("reserved 0x%x", reserved);

	sect_count = le16_to_cpu(vs->sectors);
	if (sect_count == 0)
		sect_count = le32_to_cpu(vs->total_sect);
	dbg("sect_count 0x%x", sect_count);

	fat_length = le16_to_cpu(vs->fat_length);
	if (fat_length == 0)
		fat_length = le32_to_cpu(vs->type.fat32.fat32_length);
	dbg("fat_length 0x%x", fat_length);

	fat_size = fat_length * vs->fats;
	dir_size = ((dir_entries * sizeof(struct vfat_dir_entry)) +
			(sector_size-1)) / sector_size;
	dbg("dir_size 0x%x", dir_size);

	cluster_count = sect_count - (reserved + fat_size + dir_size);
	cluster_count /= vs->sectors_per_cluster;
	dbg("cluster_count 0x%x", cluster_count);

	if (cluster_count < FAT12_MAX) {
		strcpy(id->type_version, "FAT12");
	} else if (cluster_count < FAT16_MAX) {
		strcpy(id->type_version, "FAT16");
	} else {
		strcpy(id->type_version, "FAT32");
		goto fat32;
	}

	/* the label may be an attribute in the root directory */
	root_start = (reserved + fat_size) * sector_size;
	dbg("root dir start 0x%llx", root_start);
	root_dir_entries = le16_to_cpu(vs->dir_entries);
	dbg("expected entries 0x%x", root_dir_entries);

	buf_size = root_dir_entries * sizeof(struct vfat_dir_entry);
	buf = get_buffer(id, off + root_start, buf_size);
	if (buf == NULL)
		goto found;

	dir = (struct vfat_dir_entry*) buf;

	for (i = 0; i < root_dir_entries; i++) {
		/* end marker */
		if (dir[i].name[0] == 0x00) {
			dbg("end of dir");
			break;
		}

		/* empty entry */
		if (dir[i].name[0] == FAT_ENTRY_FREE)
			continue;

		/* long name */
		if ((dir[i].attr & FAT_ATTR_MASK) == FAT_ATTR_LONG_NAME)
			continue;

		if ((dir[i].attr & (FAT_ATTR_VOLUME_ID | FAT_ATTR_DIR)) == FAT_ATTR_VOLUME_ID) {
			/* labels do not have file data */
			if (dir[i].cluster_high != 0 || dir[i].cluster_low != 0)
				continue;

			dbg("found ATTR_VOLUME_ID id in root dir");
			label = dir[i].name;
			break;
		}

		dbg("skip dir entry");
	}

	vs = (struct vfat_super_block *) get_buffer(id, off, 0x200);
	if (vs == NULL)
		return -1;

	if (label != NULL && strncmp(label, "NO NAME    ", 11) != 0) {
		set_label_raw(id, label, 11);
		set_label_string(id, label, 11);
	} else if (strncmp(vs->type.fat.label, "NO NAME    ", 11) != 0) {
		set_label_raw(id, vs->type.fat.label, 11);
		set_label_string(id, vs->type.fat.label, 11);
	}
	set_uuid(id, vs->type.fat.serno, UUID_DOS);
	goto found;

fat32:
	/* FAT32 root dir is a cluster chain like any other directory */
	buf_size = vs->sectors_per_cluster * sector_size;
	root_cluster = le32_to_cpu(vs->type.fat32.root_cluster);
	dbg("root dir cluster %u", root_cluster);
	start_data_sect = reserved + fat_size;

	next = root_cluster;
	maxloop = 100;
	while (--maxloop) {
		__u32 next_sect_off;
		__u64 next_off;
		__u64 fat_entry_off;
		int count;

		dbg("next cluster %u", next);
		next_sect_off = (next - 2) * vs->sectors_per_cluster;
		next_off = (start_data_sect + next_sect_off) * sector_size;
		dbg("cluster offset 0x%llx", next_off);

		/* get cluster */
		buf = get_buffer(id, off + next_off, buf_size);
		if (buf == NULL)
			goto found;

		dir = (struct vfat_dir_entry*) buf;
		count = buf_size / sizeof(struct vfat_dir_entry);
		dbg("expected entries 0x%x", count);

		for (i = 0; i < count; i++) {
			/* end marker */
			if (dir[i].name[0] == 0x00) {
				dbg("end of dir");
				goto fat32_label;
			}

			/* empty entry */
			if (dir[i].name[0] == FAT_ENTRY_FREE)
				continue;

			/* long name */
			if ((dir[i].attr & FAT_ATTR_MASK) == FAT_ATTR_LONG_NAME)
				continue;

			if ((dir[i].attr & (FAT_ATTR_VOLUME_ID | FAT_ATTR_DIR)) == FAT_ATTR_VOLUME_ID) {
				/* labels do not have file data */
				if (dir[i].cluster_high != 0 || dir[i].cluster_low != 0)
					continue;

				dbg("found ATTR_VOLUME_ID id in root dir");
				label = dir[i].name;
				goto fat32_label;
			}

			dbg("skip dir entry");
		}

		/* get FAT entry */
		fat_entry_off = (reserved * sector_size) + (next * sizeof(__u32));
		buf = get_buffer(id, off + fat_entry_off, buf_size);
		if (buf == NULL)
			goto found;

		/* set next cluster */
		next = le32_to_cpu(*((__u32 *) buf) & 0x0fffffff);
		if (next == 0)
			break;
	}
	if (maxloop == 0)
		dbg("reached maximum follow count of root cluster chain, give up");

fat32_label:
	vs = (struct vfat_super_block *) get_buffer(id, off, 0x200);
	if (vs == NULL)
		return -1;

	if (label != NULL && strncmp(label, "NO NAME    ", 11) != 0) {
		set_label_raw(id, label, 11);
		set_label_string(id, label, 11);
	} else if (strncmp(vs->type.fat32.label, "NO NAME    ", 11) != 0) {
		set_label_raw(id, vs->type.fat32.label, 11);
		set_label_string(id, vs->type.fat32.label, 11);
	}
	set_uuid(id, vs->type.fat32.serno, UUID_DOS);

found:
	id->usage_id = VOLUME_ID_FILESYSTEM;
	id->type_id = VOLUME_ID_VFAT;
	id->type = "vfat";

	return 0;
}

#define UDF_VSD_OFFSET			0x8000
static int probe_udf(struct volume_id *id, __u64 off)
{
	struct volume_descriptor {
		struct descriptor_tag {
			__u16	id;
			__u16	version;
			__u8	checksum;
			__u8	reserved;
			__u16	serial;
			__u16	crc;
			__u16	crc_len;
			__u32	location;
		} __attribute__((__packed__)) tag;
		union {
			struct anchor_descriptor {
				__u32	length;
				__u32	location;
			} __attribute__((__packed__)) anchor;
			struct primary_descriptor {
				__u32	seq_num;
				__u32	desc_num;
				struct dstring {
					__u8	clen;
					__u8	c[31];
				} __attribute__((__packed__)) ident;
			} __attribute__((__packed__)) primary;
		} __attribute__((__packed__)) type;
	} __attribute__((__packed__)) *vd;

	struct volume_structure_descriptor {
		__u8	type;
		__u8	id[5];
		__u8	version;
	} *vsd;

	unsigned int bs;
	unsigned int b;
	unsigned int type;
	unsigned int count;
	unsigned int loc;
	unsigned int clen;

	vsd = (struct volume_structure_descriptor *)
	      get_buffer(id, off + UDF_VSD_OFFSET, 0x200);
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
		      get_buffer(id, off + UDF_VSD_OFFSET + bs, 0x800);
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
		      get_buffer(id, off + UDF_VSD_OFFSET + (b * bs), 0x800);
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
	vd = (struct volume_descriptor *)
		get_buffer(id, off + (256 * bs), 0x200);
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
		     get_buffer(id, off + ((loc + b) * bs), 0x200);
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
	if (clen == 8)
		set_label_string(id, vd->type.primary.ident.c, 31);
	else if (clen == 16)
		set_label_unicode16(id, vd->type.primary.ident.c, BE,31);

found:
	id->usage_id = VOLUME_ID_FILESYSTEM;
	id->type_id = VOLUME_ID_UDF;
	id->type = "udf";

	return 0;
}

#define ISO_SUPERBLOCK_OFFSET		0x8000
#define ISO_SECTOR_SIZE			0x800
#define ISO_VD_OFFSET			(ISO_SUPERBLOCK_OFFSET + ISO_SECTOR_SIZE)
#define ISO_VD_PRIMARY			0x1
#define ISO_VD_SUPPLEMENTARY		0x2
#define ISO_VD_END			0xff
#define ISO_VD_MAX			16
static int probe_iso9660(struct volume_id *id, __u64 off)
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

	is = (union iso_super_block *)
	     get_buffer(id, off + ISO_SUPERBLOCK_OFFSET, 0x200);
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
			is = (union iso_super_block *) 
			     get_buffer (id, off + vd_offset, 0x200);
			if (is == NULL || is->iso.type == ISO_VD_END)
				break;
			if (is->iso.type == ISO_VD_SUPPLEMENTARY) {
				dbg("found ISO supplementary VD at offset 0x%llx", off + vd_offset);
				set_label_raw(id, is->iso.volume_id, 32);
				set_label_unicode16(id, is->iso.volume_id, BE, 32);
				found_svd = 1;
				break;
			}
			vd_offset += ISO_SECTOR_SIZE;
		}

		if (!found_svd ||
		    (found_svd && !strncmp(root_label, id->label, 16)))
		{
			set_label_raw(id, root_label, 32);
			set_label_string(id, root_label, 32);
		}
		goto found;
	}
	if (strncmp(is->hs.id, "CDROM", 5) == 0)
		goto found;
	return -1;

found:
	id->usage_id = VOLUME_ID_FILESYSTEM;
	id->type_id = VOLUME_ID_ISO9660;
	id->type = "iso9660";

	return 0;
}

#define UFS_MAGIC			0x00011954
#define UFS2_MAGIC			0x19540119
#define UFS_MAGIC_FEA			0x00195612
#define UFS_MAGIC_LFN			0x00095014


static int probe_ufs(struct volume_id *id, __u64 off)
{
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
				__s8  fs_fsmnt[468];
				__u8   fs_volname[32];
				__u64  fs_swuid;
				__s32  fs_pad;
				__u32   fs_cgrotor;
				__u32   fs_ocsp[28];
				__u32   fs_contigdirs;
				__u32   fs_csp;	
				__u32   fs_maxcluster;
				__u32   fs_active;
				__s32   fs_old_cpc;
				__s32   fs_maxbsize;
				__s64   fs_sparecon64[17];
				__s64   fs_sblockloc;
				struct  ufs2_csum_total {
					__u64	cs_ndir;
					__u64	cs_nbfree;
					__u64	cs_nifree;
					__u64	cs_nffree;
					__u64	cs_numclusters;
					__u64	cs_spare[3];
				} __attribute__((__packed__)) fs_cstotal;
				struct  ufs_timeval {
					__s32	tv_sec;
					__s32	tv_usec;
				} __attribute__((__packed__)) fs_time;
				__s64    fs_size;
				__s64    fs_dsize;
				__u64    fs_csaddr;
				__s64    fs_pendingblocks;
				__s32    fs_pendinginodes;
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
	} __attribute__((__packed__)) *ufs;

	__u32	magic;
	int 	i;
	int	offsets[] = {0, 8, 64, 256, -1};

	for (i = 0; offsets[i] >= 0; i++) {	
		ufs = (struct ufs_super_block *)
			get_buffer(id, off + (offsets[i] * 0x400), 0x800);
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
	id->usage_id = VOLUME_ID_FILESYSTEM;
	id->type_id = VOLUME_ID_UFS;
	id->type = "ufs";

	return 0;
}

static int probe_mac_partition_map(struct volume_id *id, __u64 off)
{
	struct mac_driver_desc {
		__u8	signature[2];
		__u16	block_size;
		__u32	block_count;
	} __attribute__((__packed__)) *driver;

	struct mac_partition {
		__u8	signature[2];
		__u16	res1;
		__u32	map_count;
		__u32	start_block;
		__u32	block_count;
		__u8	name[32];
		__u8	type[32];
	} __attribute__((__packed__)) *part;

	const __u8 *buf;

	buf = get_buffer(id, off, 0x200);
	if (buf == NULL)
		return -1;

	part = (struct mac_partition *) buf;
	if ((strncmp(part->signature, "PM", 2) == 0) &&
	    (strncmp(part->type, "Apple_partition_map", 19) == 0)) {
		/* linux creates an own subdevice for the map
		 * just return the type if the drive header is missing */
		id->usage_id = VOLUME_ID_PARTITIONTABLE;
		id->type_id = VOLUME_ID_MACPARTMAP;
		id->type = "mac_partition_map";
		return 0;
	}

	driver = (struct mac_driver_desc *) buf;
	if (strncmp(driver->signature, "ER", 2) == 0) {
		/* we are on a main device, like a CD
		 * just try to probe the first partition from the map */
		unsigned int bsize = be16_to_cpu(driver->block_size);
		int part_count;
		int i;

		/* get first entry of partition table */
		buf = get_buffer(id, off +  bsize, 0x200);
		if (buf == NULL)
			return -1;

		part = (struct mac_partition *) buf;
		if (strncmp(part->signature, "PM", 2) != 0)
			return -1;

		part_count = be32_to_cpu(part->map_count);
		dbg("expecting %d partition entries", part_count);

		if (id->partitions != NULL)
			free(id->partitions);
		id->partitions =
			malloc(part_count * sizeof(struct volume_id_partition));
		if (id->partitions == NULL)
			return -1;
		memset(id->partitions, 0x00, sizeof(struct volume_id_partition));

		id->partition_count = part_count;

		for (i = 0; i < part_count; i++) {
			__u64 poff;
			__u64 plen;

			buf = get_buffer(id, off + ((i+1) * bsize), 0x200);
			if (buf == NULL)
				return -1;

			part = (struct mac_partition *) buf;
			if (strncmp(part->signature, "PM", 2) != 0)
				return -1;

			poff = be32_to_cpu(part->start_block) * bsize;
			plen = be32_to_cpu(part->block_count) * bsize;
			dbg("found '%s' partition entry at 0x%llx, len 0x%llx",
			    part->type, poff, plen);

			id->partitions[i].off = poff;
			id->partitions[i].len = plen;

			if (strncmp(part->type, "Apple_Free", 10) == 0) {
				id->partitions[i].usage_id = VOLUME_ID_UNUSED;
			} else if (strncmp(part->type, "Apple_partition_map", 19) == 0) {
				id->partitions[i].usage_id = VOLUME_ID_PARTITIONTABLE;
				id->partitions[i].type_id = VOLUME_ID_MACPARTMAP;
			} else {
				id->partitions[i].usage_id = VOLUME_ID_UNPROBED;
			}
		}
		id->usage_id = VOLUME_ID_PARTITIONTABLE;
		id->type_id = VOLUME_ID_MACPARTMAP;
		id->type = "mac_partition_map";
		return 0;
	}

	return -1;
}

#define HFS_SUPERBLOCK_OFFSET		0x400
#define HFS_NODE_LEAF			0xff
#define HFSPLUS_POR_CNID		1
#define HFSPLUS_EXTENT_COUNT		8
static int probe_hfs_hfsplus(struct volume_id *id, __u64 off)
{
	struct hfs_finder_info{
		__u32	boot_folder;
		__u32	start_app;
		__u32	open_folder;
		__u32	os9_folder;
		__u32	reserved;
		__u32	osx_folder;
		__u8	id[8];
	} __attribute__((__packed__));

	struct hfs_mdb {
		__u8	signature[2];
		__u32	cr_date;
		__u32	ls_Mod;
		__u16	atrb;
		__u16	nm_fls;
		__u16	vbm_st;
		__u16	alloc_ptr;
		__u16	nm_al_blks;
		__u32	al_blk_size;
		__u32	clp_size;
		__u16	al_bl_st;
		__u32	nxt_cnid;
		__u16	free_bks;
		__u8	label_len;
		__u8	label[27];
		__u32	vol_bkup;
		__u16	vol_seq_num;
		__u32	wr_cnt;
		__u32	xt_clump_size;
		__u32	ct_clump_size;
		__u16	num_root_dirs;
		__u32	file_count;
		__u32	dir_count;
		struct hfs_finder_info finder_info;
		__u8	embed_sig[2];
		__u16	embed_startblock;
		__u16	embed_blockcount;
	} __attribute__((__packed__)) *hfs;

	struct hfsplus_bnode_descriptor {
		__u32	next;
		__u32	prev;
		__u8	type;
		__u8	height;
		__u16	num_recs;
		__u16	reserved;
	} __attribute__((__packed__));

	struct hfsplus_bheader_record {
		__u16	depth;
		__u32	root;
		__u32	leaf_count;
		__u32	leaf_head;
		__u32	leaf_tail;
		__u16	node_size;
	} __attribute__((__packed__));

	struct hfsplus_catalog_key {
		__u16	key_len;
		__u32	parent_id;
		__u16	unicode_len;
		__u8	unicode[255 * 2];
	} __attribute__((__packed__));

	struct hfsplus_extent {
		__u32 start_block;
		__u32 block_count;
	} __attribute__((__packed__));

	struct hfsplus_fork {
		__u64 total_size;
        	__u32 clump_size;
		__u32 total_blocks;
		struct hfsplus_extent extents[HFSPLUS_EXTENT_COUNT];
	} __attribute__((__packed__));

	struct hfsplus_vol_header {
		__u8	signature[2];
		__u16	version;
		__u32	attributes;
		__u32	last_mount_vers;
		__u32	reserved;
		__u32	create_date;
		__u32	modify_date;
		__u32	backup_date;
		__u32	checked_date;
		__u32	file_count;
		__u32	folder_count;
		__u32	blocksize;
		__u32	total_blocks;
		__u32	free_blocks;
		__u32	next_alloc;
		__u32	rsrc_clump_sz;
		__u32	data_clump_sz;
		__u32	next_cnid;
		__u32	write_count;
		__u64	encodings_bmp;
		struct hfs_finder_info finder_info;
		struct hfsplus_fork alloc_file;
		struct hfsplus_fork ext_file;
		struct hfsplus_fork cat_file;
		struct hfsplus_fork attr_file;
		struct hfsplus_fork start_file;
	} __attribute__((__packed__)) *hfsplus;

	unsigned int blocksize;
	unsigned int cat_block;
	unsigned int ext_block_start;
	unsigned int ext_block_count;
	int ext;
	unsigned int leaf_node_head;
	unsigned int leaf_node_count;
	unsigned int leaf_node_size;
	unsigned int leaf_block;
	__u64 leaf_off;
	unsigned int alloc_block_size;
	unsigned int alloc_first_block;
	unsigned int embed_first_block;
	unsigned int record_count;
	struct hfsplus_bnode_descriptor *descr;
	struct hfsplus_bheader_record *bnode;
	struct hfsplus_catalog_key *key;
	unsigned int	label_len;
	struct hfsplus_extent extents[HFSPLUS_EXTENT_COUNT];
	const __u8 *buf;

	buf = get_buffer(id, off + HFS_SUPERBLOCK_OFFSET, 0x200);
	if (buf == NULL)
                return -1;

	hfs = (struct hfs_mdb *) buf;
	if (strncmp(hfs->signature, "BD", 2) != 0)
		goto checkplus;

	/* it may be just a hfs wrapper for hfs+ */
	if (strncmp(hfs->embed_sig, "H+", 2) == 0) {
		alloc_block_size = be32_to_cpu(hfs->al_blk_size);
		dbg("alloc_block_size 0x%x", alloc_block_size);

		alloc_first_block = be16_to_cpu(hfs->al_bl_st);
		dbg("alloc_first_block 0x%x", alloc_first_block);

		embed_first_block = be16_to_cpu(hfs->embed_startblock);
		dbg("embed_first_block 0x%x", embed_first_block);

		off += (alloc_first_block * 512) +
		       (embed_first_block * alloc_block_size);
		dbg("hfs wrapped hfs+ found at offset 0x%llx", off);

		buf = get_buffer(id, off + HFS_SUPERBLOCK_OFFSET, 0x200);
		if (buf == NULL)
			return -1;
		goto checkplus;
	}

	if (hfs->label_len > 0 && hfs->label_len < 28) {
		set_label_raw(id, hfs->label, hfs->label_len);
		set_label_string(id, hfs->label, hfs->label_len) ;
	}

	set_uuid(id, hfs->finder_info.id, UUID_HFS);

	id->usage_id = VOLUME_ID_FILESYSTEM;
	id->type_id = VOLUME_ID_HFS;
	id->type = "hfs";

	return 0;

checkplus:
	hfsplus = (struct hfsplus_vol_header *) buf;
	if (strncmp(hfsplus->signature, "H+", 2) == 0)
		goto hfsplus;
	if (strncmp(hfsplus->signature, "HX", 2) == 0)
		goto hfsplus;
	return -1;

hfsplus:
	set_uuid(id, hfsplus->finder_info.id, UUID_HFS);

	blocksize = be32_to_cpu(hfsplus->blocksize);
	dbg("blocksize %u", blocksize);

	memcpy(extents, hfsplus->cat_file.extents, sizeof(extents));
	cat_block = be32_to_cpu(extents[0].start_block);
	dbg("catalog start block 0x%x", cat_block);

	buf = get_buffer(id, off + (cat_block * blocksize), 0x2000);
	if (buf == NULL)
		goto found;

	bnode = (struct hfsplus_bheader_record *)
		&buf[sizeof(struct hfsplus_bnode_descriptor)];

	leaf_node_head = be32_to_cpu(bnode->leaf_head);
	dbg("catalog leaf node 0x%x", leaf_node_head);

	leaf_node_size = be16_to_cpu(bnode->node_size);
	dbg("leaf node size 0x%x", leaf_node_size);

	leaf_node_count = be32_to_cpu(bnode->leaf_count);
	dbg("leaf node count 0x%x", leaf_node_count);
	if (leaf_node_count == 0)
		goto found;

	leaf_block = (leaf_node_head * leaf_node_size) / blocksize;

	/* get physical location */
	for (ext = 0; ext < HFSPLUS_EXTENT_COUNT; ext++) {
		ext_block_start = be32_to_cpu(extents[ext].start_block);
		ext_block_count = be32_to_cpu(extents[ext].block_count);
		dbg("extent start block 0x%x, count 0x%x", ext_block_start, ext_block_count);

		if (ext_block_count == 0)
			goto found;

		/* this is our extent */
		if (leaf_block < ext_block_count)
			break;

		leaf_block -= ext_block_count;
	}
	if (ext == HFSPLUS_EXTENT_COUNT)
		goto found;
	dbg("found block in extent %i", ext);

	leaf_off = (ext_block_start + leaf_block) * blocksize;

	buf = get_buffer(id, off + leaf_off, leaf_node_size);
	if (buf == NULL)
		goto found;

	descr = (struct hfsplus_bnode_descriptor *) buf;
	dbg("descriptor type 0x%x", descr->type);

	record_count = be16_to_cpu(descr->num_recs);
	dbg("number of records %u", record_count);
	if (record_count == 0)
		goto found;

	if (descr->type != HFS_NODE_LEAF)
		goto found;

	key = (struct hfsplus_catalog_key *)
		&buf[sizeof(struct hfsplus_bnode_descriptor)];

	dbg("parent id 0x%x", be32_to_cpu(key->parent_id));
	if (be32_to_cpu(key->parent_id) != HFSPLUS_POR_CNID)
		goto found;

	label_len = be16_to_cpu(key->unicode_len) * 2;
	dbg("label unicode16 len %i", label_len);
	set_label_raw(id, key->unicode, label_len);
	set_label_unicode16(id, key->unicode, BE, label_len);

found:
	id->usage_id = VOLUME_ID_FILESYSTEM;
	id->type_id = VOLUME_ID_HFSPLUS;
	id->type = "hfsplus";

	return 0;
}

#define MFT_RECORD_VOLUME			3
#define MFT_RECORD_ATTR_VOLUME_NAME		0x60
#define MFT_RECORD_ATTR_VOLUME_INFO		0x70
#define MFT_RECORD_ATTR_OBJECT_ID		0x40
#define MFT_RECORD_ATTR_END			0xffffffffu
static int probe_ntfs(struct volume_id *id, __u64 off)
{
	struct ntfs_super_block {
		__u8	jump[3];
		__u8	oem_id[8];
		__u16	bytes_per_sector;
		__u8	sectors_per_cluster;
		__u16	reserved_sectors;
		__u8	fats;
		__u16	root_entries;
		__u16	sectors;
		__u8	media_type;
		__u16	sectors_per_fat;
		__u16	sectors_per_track;
		__u16	heads;
		__u32	hidden_sectors;
		__u32	large_sectors;
		__u16	unused[2];
		__u64	number_of_sectors;
		__u64	mft_cluster_location;
		__u64	mft_mirror_cluster_location;
		__s8	cluster_per_mft_record;
		__u8	reserved1[3];
		__s8	cluster_per_index_record;
		__u8	reserved2[3];
		__u8	volume_serial[8];
		__u16	checksum;
	} __attribute__((__packed__)) *ns;

	struct master_file_table_record {
		__u8	magic[4];
		__u16	usa_ofs;
		__u16	usa_count;
		__u64	lsn;
		__u16	sequence_number;
		__u16	link_count;
		__u16	attrs_offset;
		__u16	flags;
		__u32	bytes_in_use;
		__u32	bytes_allocated;
	} __attribute__((__packed__)) *mftr;

	struct file_attribute {
		__u32	type;
		__u32	len;
		__u8	non_resident;
		__u8	name_len;
		__u16	name_offset;
		__u16	flags;
		__u16	instance;
		__u32	value_len;
		__u16	value_offset;
	} __attribute__((__packed__)) *attr;

	struct volume_info {
		__u64 reserved;
		__u8 major_ver;
		__u8 minor_ver;
	} __attribute__((__packed__)) *info;

	unsigned int sector_size;
	unsigned int cluster_size;
	__u64 mft_cluster;
	__u64 mft_off;
	unsigned int mft_record_size;
	unsigned int attr_type;
	unsigned int attr_off;
	unsigned int attr_len;
	unsigned int val_off;
	unsigned int val_len;
	const __u8 *buf;
	const __u8 *val;

	ns = (struct ntfs_super_block *) get_buffer(id, off, 0x200);
	if (ns == NULL)
		return -1;

	if (strncmp(ns->oem_id, "NTFS", 4) != 0)
		return -1;

	set_uuid(id, ns->volume_serial, UUID_NTFS);

	sector_size = le16_to_cpu(ns->bytes_per_sector);
	cluster_size = ns->sectors_per_cluster * sector_size;
	mft_cluster = le64_to_cpu(ns->mft_cluster_location);
	mft_off = mft_cluster * cluster_size;

	if (ns->cluster_per_mft_record < 0)
		/* size = -log2(mft_record_size); normally 1024 Bytes */
		mft_record_size = 1 << -ns->cluster_per_mft_record;
	else
		mft_record_size = ns->cluster_per_mft_record * cluster_size;

	dbg("sectorsize  0x%x", sector_size);
	dbg("clustersize 0x%x", cluster_size);
	dbg("mftcluster  %lli", mft_cluster);
	dbg("mftoffset  0x%llx", mft_off);
	dbg("cluster per mft_record  %i", ns->cluster_per_mft_record);
	dbg("mft record size  %i", mft_record_size);

	buf = get_buffer(id, off + mft_off + (MFT_RECORD_VOLUME * mft_record_size),
			 mft_record_size);
	if (buf == NULL)
		goto found;

	mftr = (struct master_file_table_record*) buf;

	dbg("mftr->magic '%c%c%c%c'", mftr->magic[0], mftr->magic[1], mftr->magic[2], mftr->magic[3]);
	if (strncmp(mftr->magic, "FILE", 4) != 0)
		goto found;

	attr_off = le16_to_cpu(mftr->attrs_offset);
	dbg("file $Volume's attributes are at offset %i", attr_off);

	while (1) {
		attr = (struct file_attribute*) &buf[attr_off];
		attr_type = le32_to_cpu(attr->type);
		attr_len = le16_to_cpu(attr->len);
		val_off = le16_to_cpu(attr->value_offset);
		val_len = le32_to_cpu(attr->value_len);
		attr_off += attr_len;

		if (attr_len == 0)
			break;

		if (attr_off >= mft_record_size)
			break;

		if (attr_type == MFT_RECORD_ATTR_END)
			break;

		dbg("found attribute type 0x%x, len %i, at offset %i",
		    attr_type, attr_len, attr_off);

		if (attr_type == MFT_RECORD_ATTR_VOLUME_INFO) {
			dbg("found info, len %i", val_len);
			info = (struct volume_info*) (((__u8 *) attr) + val_off);
			snprintf(id->type_version, VOLUME_ID_FORMAT_SIZE-1,
				 "%u.%u", info->major_ver, info->minor_ver);
		}

		if (attr_type == MFT_RECORD_ATTR_VOLUME_NAME) {
			dbg("found label, len %i", val_len);
			if (val_len > VOLUME_ID_LABEL_SIZE)
				val_len = VOLUME_ID_LABEL_SIZE;

			val = ((__u8 *) attr) + val_off;
			set_label_raw(id, val, val_len);
			set_label_unicode16(id, val, LE, val_len);
		}
	}

found:
	id->usage_id = VOLUME_ID_FILESYSTEM;
	id->type_id = VOLUME_ID_NTFS;
	id->type = "ntfs";

	return 0;
}

#define LARGEST_PAGESIZE			0x4000
static int probe_swap(struct volume_id *id, __u64 off)
{
	struct swap_header_v1_2 {
		__u8	bootbits[1024];
		__u32	version;
		__u32	last_page;
		__u32	nr_badpages;
		__u8	uuid[16];
		__u8	volume_name[16];
	} __attribute__((__packed__)) *sw;

	const __u8 *buf;
	unsigned int page;

	/* the swap signature is at the end of the PAGE_SIZE */
	for (page = 0x1000; page <= LARGEST_PAGESIZE; page <<= 1) {
			buf = get_buffer(id, off + page-10, 10);
			if (buf == NULL)
				return -1;

			if (strncmp(buf, "SWAP-SPACE", 10) == 0) {
				strcpy(id->type_version, "1");
				goto found;
			}

			if (strncmp(buf, "SWAPSPACE2", 10) == 0) {
				sw = (struct swap_header_v1_2 *) get_buffer(id, off, sizeof(struct swap_header_v1_2));
				if (sw == NULL)
					return -1;
				strcpy(id->type_version, "2");
				set_label_raw(id, sw->volume_name, 16);
				set_label_string(id, sw->volume_name, 16);
				set_uuid(id, sw->uuid, UUID_DCE);
				goto found;
			}
	}
	return -1;

found:
	id->usage_id = VOLUME_ID_OTHER;
	id->type_id = VOLUME_ID_SWAP;
	id->type = "swap";

	return 0;
}

/* probe volume for filesystem type and try to read label+uuid */
int volume_id_probe(struct volume_id *id,
		    enum volume_id_type type,
		    unsigned long long off,
		    unsigned long long size)
{
	int rc;

	dbg("called with size=0x%llx", size);

	if (id == NULL)
		return -EINVAL;

	switch (type) {
	case VOLUME_ID_MSDOSPARTTABLE:
		rc = probe_msdos_part_table(id, off);
		break;
	case VOLUME_ID_EXT3:
	case VOLUME_ID_EXT2:
		rc = probe_ext(id, off);
		break;
	case VOLUME_ID_REISERFS:
		rc = probe_reiserfs(id, off);
		break;
	case VOLUME_ID_XFS:
		rc = probe_xfs(id, off);
		break;
	case VOLUME_ID_JFS:
		rc = probe_jfs(id, off);
		break;
	case VOLUME_ID_VFAT:
		rc = probe_vfat(id, off);
		break;
	case VOLUME_ID_UDF:
		rc = probe_udf(id, off);
		break;
	case VOLUME_ID_ISO9660:
		rc = probe_iso9660(id, off);
		break;
	case VOLUME_ID_MACPARTMAP:
		rc = probe_mac_partition_map(id, off);
		break;
	case VOLUME_ID_HFS:
	case VOLUME_ID_HFSPLUS:
		rc = probe_hfs_hfsplus(id, off);
		break;
	case VOLUME_ID_UFS:
		rc = probe_ufs(id, off);
		break;
	case VOLUME_ID_NTFS:
		rc = probe_ntfs(id, off);
		break;
	case VOLUME_ID_SWAP:
		rc = probe_swap(id, off);
		break;
	case VOLUME_ID_LINUX_RAID:
		rc = probe_linux_raid(id, off, size);
		break;
	case VOLUME_ID_LVM1:
		rc = probe_lvm1(id, off);
		break;
	case VOLUME_ID_LVM2:
		rc = probe_lvm2(id, off);
		break;
	case VOLUME_ID_HPTRAID:
		rc = probe_highpoint_ataraid(id, off);
		break;
	case VOLUME_ID_ALL:
	default:
		/* probe for raid first, cause fs probes may be successful on raid members */
		rc = probe_linux_raid(id, off, size);
		if (rc == 0)
			break;
		rc = probe_lvm1(id, off);
		if (rc == 0)
			break;
		rc = probe_lvm2(id, off);
		if (rc == 0)
			break;
		rc = probe_highpoint_ataraid(id, off);
		if (rc == 0)
			break;

		/* signature in the first block, only small buffer needed */
		rc = probe_vfat(id, off);
		if (rc == 0)
			break;
		rc = probe_mac_partition_map(id, off);
		if (rc == 0)
			break;
		rc = probe_xfs(id, off);
		if (rc == 0)
			break;

		/* fill buffer with maximum */
		get_buffer(id, 0, SB_BUFFER_SIZE);

		rc = probe_swap(id, off);
		if (rc == 0)
			break;
		rc = probe_ext(id, off);
		if (rc == 0)
			break;
		rc = probe_reiserfs(id, off);
		if (rc == 0)
			break;
		rc = probe_jfs(id, off);
		if (rc == 0)
			break;
		rc = probe_udf(id, off);
		if (rc == 0)
			break;
		rc = probe_iso9660(id, off);
		if (rc == 0)
			break;
		rc = probe_hfs_hfsplus(id, off);
		if (rc == 0)
			break;
		rc = probe_ufs(id, off);
		if (rc == 0)
			break;
		rc = probe_ntfs(id, off);
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
	if (fd < 0) {
		dbg("unable to open '%s'", path);
		return NULL;
	}

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
	__u8 tmp_node[VOLUME_ID_PATH_MAX];

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

	if (id->partitions != NULL)
		free(id->partitions);

	free(id);
}
