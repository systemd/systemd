/*
 * volume_id - reads partition label and uuid
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

#ifndef _VOLUME_ID_H_
#define _VOLUME_ID_H_

#define VOLUME_ID_VERSION		27

#define VOLUME_ID_LABEL_SIZE		64
#define VOLUME_ID_UUID_SIZE		16
#define VOLUME_ID_UUID_STRING_SIZE	37
#define VOLUME_ID_FORMAT_SIZE		32
#define VOLUME_ID_PATH_MAX		256
#define VOLUME_ID_PARTITIONS_MAX	256

enum volume_id_usage {
	VOLUME_ID_UNUSED,
	VOLUME_ID_UNPROBED,
	VOLUME_ID_OTHER,
	VOLUME_ID_FILESYSTEM,
	VOLUME_ID_PARTITIONTABLE,
	VOLUME_ID_RAID,
};

enum volume_id_type {
	VOLUME_ID_ALL,
	VOLUME_ID_MSDOSPARTTABLE,
	VOLUME_ID_MSDOSEXTENDED,
	VOLUME_ID_SWAP,
	VOLUME_ID_EXT2,
	VOLUME_ID_EXT3,
	VOLUME_ID_REISERFS,
	VOLUME_ID_XFS,
	VOLUME_ID_JFS,
	VOLUME_ID_VFAT,
	VOLUME_ID_UDF,
	VOLUME_ID_ISO9660,
	VOLUME_ID_NTFS,
	VOLUME_ID_MACPARTMAP,
	VOLUME_ID_HFS,
	VOLUME_ID_HFSPLUS,
	VOLUME_ID_UFS,
	VOLUME_ID_LINUX_RAID,
	VOLUME_ID_LVM1,
	VOLUME_ID_LVM2,
	VOLUME_ID_HPTRAID,
};

struct volume_id_partition {
	enum		volume_id_usage usage_id;
	enum		volume_id_type type_id;
	char		*type;
	unsigned long long off;
	unsigned long long len;
	unsigned int partition_type_raw;
};

struct volume_id {
	unsigned char	label_raw[VOLUME_ID_LABEL_SIZE];
	unsigned int	label_raw_len;
	char		label[VOLUME_ID_LABEL_SIZE+1];
	unsigned char	uuid_raw[VOLUME_ID_UUID_SIZE];
	char		uuid[VOLUME_ID_UUID_STRING_SIZE];
	enum		volume_id_usage usage_id;
	enum		volume_id_type type_id;
	char		*type;
	char		type_version[VOLUME_ID_FORMAT_SIZE];
	struct volume_id_partition *partitions;
	unsigned int	partition_count;
	int		fd;
	unsigned char	*sbbuf;
	unsigned int	sbbuf_len;
	unsigned char	*seekbuf;
	unsigned long long seekbuf_off;
	unsigned int	seekbuf_len;
	int		fd_close;
};

/* open volume by already open file descriptor */
extern struct volume_id *volume_id_open_fd(int fd);

/* open volume by device node */
extern struct volume_id *volume_id_open_node(const char *path);

/* open volume by major/minor */
extern struct volume_id *volume_id_open_dev_t(dev_t devt);

/* probe volume for filesystem type and try to read label/uuid */
extern int volume_id_probe(struct volume_id *id, enum volume_id_type type,
			   unsigned long long off, unsigned long long size);

/* free allocated device info */
extern void volume_id_close(struct volume_id *id);

#endif
