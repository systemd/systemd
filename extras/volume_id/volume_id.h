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

#define VOLUME_ID_VERSION		004

#define VOLUME_ID_LABEL_SIZE		64
#define VOLUME_ID_UUID_SIZE		16
#define VOLUME_ID_UUID_STRING_SIZE	37
#define VOLUME_ID_PATH_MAX		255


enum filesystem_type {
	ALL,
	EXT2,
	EXT3,
	REISER,
	XFS,
	JFS,
	MSDOS,
	VFAT,
	UDF,
	ISO9660,
	NTFS,
	SWAP
};

struct volume_id {
	unsigned char	label_raw[VOLUME_ID_LABEL_SIZE];
	unsigned int	label_raw_len;
	char		label_string[VOLUME_ID_LABEL_SIZE+1];
	unsigned char	uuid[VOLUME_ID_UUID_SIZE];
	char		uuid_string[VOLUME_ID_UUID_STRING_SIZE];
	enum		filesystem_type fs_type;
	char		*fs_name;
	int		fd;
	unsigned char	*sbbuf;
	unsigned int	sbbuf_len;
	unsigned char	*seekbuf;
	unsigned int	seekbuf_off;
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
extern int volume_id_probe(struct volume_id *id, enum filesystem_type fs_type);

/* free allocated device info */
extern void volume_id_close(struct volume_id *id);

#endif
