/*
 * volume_id - reads partition label and uuid
 *
 * Copyright (C) 2004 Kay Sievers <kay.sievers@vrfy.org>
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

#ifndef _VOLUME_ID_H_
#define _VOLUME_ID_H_

#define VOLUME_ID_VERSION		001

#define VOLUME_ID_LABEL_SIZE		16
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
	NTFS,
	SWAP
};

struct volume_id {
	char label[VOLUME_ID_LABEL_SIZE];
	char label_string[VOLUME_ID_LABEL_SIZE+1];
	unsigned char uuid[VOLUME_ID_UUID_SIZE];
	char uuid_string[VOLUME_ID_UUID_STRING_SIZE];
	enum filesystem_type fs_type;
	char *fs_name;
	int fd;
	char *buf;
	int fd_close;
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
