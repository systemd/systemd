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

#ifndef _VOLUME_ID_UTIL_
#define _VOLUME_ID_UTIL_

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

/* size of superblock buffer, reiserfs block is at 64k */
#define SB_BUFFER_SIZE				0x11000
/* size of seek buffer, FAT cluster is 32k max */
#define SEEK_BUFFER_SIZE			0x10000

/* probe volume for all known filesystems in specific order */
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
#define cpu_to_le32(x) (x)
#define cpu_to_be32(x) bswap32(x)
#elif (__BYTE_ORDER == __BIG_ENDIAN)
#define le16_to_cpu(x) bswap16(x)
#define le32_to_cpu(x) bswap32(x)
#define le64_to_cpu(x) bswap64(x)
#define be16_to_cpu(x) (x)
#define be32_to_cpu(x) (x)
#define cpu_to_le32(x) bswap32(x)
#define cpu_to_be32(x) (x)
#endif

enum uuid_format {
	UUID_DCE_STRING,
	UUID_DCE,
	UUID_DOS,
	UUID_NTFS,
	UUID_HFS,
};

enum endian {
	LE = 0,
	BE = 1
};

extern void volume_id_set_usage(struct volume_id *id, enum volume_id_usage usage_id);
extern void volume_id_set_usage_part(struct volume_id_partition *part, enum volume_id_usage usage_id);
extern void volume_id_set_label_raw(struct volume_id *id, const __u8 *buf, unsigned int count);
extern void volume_id_set_label_string(struct volume_id *id, const __u8 *buf, unsigned int count);
extern void volume_id_set_label_unicode16(struct volume_id *id, const __u8 *buf, enum endian endianess, unsigned int count);
extern void volume_id_set_uuid(struct volume_id *id, const __u8 *buf, enum uuid_format format);
extern __u8 *volume_id_get_buffer(struct volume_id *id, __u64 off, unsigned int len);
extern void volume_id_free_buffer(struct volume_id *id);

#endif /* _VOLUME_ID_UTIL_ */

