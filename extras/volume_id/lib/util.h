/*
 * volume_id - reads filesystem label and uuid
 *
 * Copyright (C) 2005-2006 Kay Sievers <kay.sievers@vrfy.org>
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
 */

#ifndef _VOLUME_ID_UTIL_
#define _VOLUME_ID_UTIL_

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <endian.h>
#include <byteswap.h>
#include <syslog.h>

#define err(format, arg...)	volume_id_log_fn(LOG_ERR, __FILE__, __LINE__, format, ##arg)
#define info(format, arg...)	volume_id_log_fn(LOG_INFO, __FILE__, __LINE__, format, ##arg)
#ifdef DEBUG
#define dbg(format, arg...)	volume_id_log_fn(LOG_DEBUG, __FILE__, __LINE__, format, ##arg)
#else
#define dbg(format, arg...)	do { } while (0)
#endif

/* size of superblock buffer, reiserfs block is at 64k */
#define SB_BUFFER_SIZE				0x11000
/* size of seek buffer, FAT cluster is 32k max */
#define SEEK_BUFFER_SIZE			0x10000

#ifdef __BYTE_ORDER
#if (__BYTE_ORDER == __LITTLE_ENDIAN)
#define le16_to_cpu(x) (x)
#define le32_to_cpu(x) (x)
#define le64_to_cpu(x) (x)
#define be16_to_cpu(x) bswap_16(x)
#define be32_to_cpu(x) bswap_32(x)
#define cpu_to_le16(x) (x)
#define cpu_to_le32(x) (x)
#define cpu_to_be32(x) bswap_32(x)
#elif (__BYTE_ORDER == __BIG_ENDIAN)
#define le16_to_cpu(x) bswap_16(x)
#define le32_to_cpu(x) bswap_32(x)
#define le64_to_cpu(x) bswap_64(x)
#define be16_to_cpu(x) (x)
#define be32_to_cpu(x) (x)
#define cpu_to_le16(x) bswap_16(x)
#define cpu_to_le32(x) bswap_32(x)
#define cpu_to_be32(x) (x)
#endif
#endif /* __BYTE_ORDER */

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

extern void volume_id_set_unicode16(char *str, size_t len, const uint8_t *buf, enum endian endianess, size_t count);
extern void volume_id_set_usage(struct volume_id *id, enum volume_id_usage usage_id);
extern void volume_id_set_label_raw(struct volume_id *id, const uint8_t *buf, size_t count);
extern void volume_id_set_label_string(struct volume_id *id, const uint8_t *buf, size_t count);
extern void volume_id_set_label_unicode16(struct volume_id *id, const uint8_t *buf, enum endian endianess, size_t count);
extern void volume_id_set_uuid(struct volume_id *id, const uint8_t *buf, enum uuid_format format);
extern uint8_t *volume_id_get_buffer(struct volume_id *id, uint64_t off, size_t len);
extern void volume_id_free_buffer(struct volume_id *id);

#endif /* _VOLUME_ID_UTIL_ */

