/*
 * volume_id - reads volume label and uuid
 *
 * Copyright (C) 2005-2007 Kay Sievers <kay.sievers@vrfy.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _LIBVOLUME_ID_PRIVATE_H_
#define _LIBVOLUME_ID_PRIVATE_H_

#include <stdint.h>
#include <stddef.h>
#include <endian.h>
#include <byteswap.h>
#include <syslog.h>

#include "libvolume_id.h"

#define ALLOWED_CHARS			"#+-.:=@_"

#ifndef PACKED
#define PACKED				__attribute__((packed))
#endif

static inline void __attribute__ ((format(printf, 1, 2)))
log_null(const char *format, ...) {}

#define err(format, arg...)	volume_id_log_fn(LOG_ERR, __FILE__, __LINE__, format, ##arg)
#define info(format, arg...)	volume_id_log_fn(LOG_INFO, __FILE__, __LINE__, format, ##arg)
#ifdef DEBUG
#define dbg(format, arg...)	volume_id_log_fn(LOG_DEBUG, __FILE__, __LINE__, format, ##arg)
#else
#define dbg(format, arg...)	log_null(format, ##arg)
#endif

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
#endif /* __BYTE_ORDER */

enum uuid_format {
	UUID_STRING,
	UUID_HEX_STRING,
	UUID_DCE,
	UUID_DOS,
	UUID_64BIT_LE,
	UUID_MD,
	UUID_LVM,
};

enum endian {
	LE = 0,
	BE = 1
};

#define VOLUME_ID_LABEL_SIZE			64
#define VOLUME_ID_UUID_SIZE			36
#define VOLUME_ID_FORMAT_SIZE			32
#define VOLUME_ID_PATH_MAX			256
#define VOLUME_ID_PARTITIONS_MAX		256

/* size of superblock buffer, reiserfs block is at 64k */
#define SB_BUFFER_SIZE				0x11000
/* size of seek buffer, FAT cluster is 32k max */
#define SEEK_BUFFER_SIZE			0x10000

enum volume_id_usage {
	VOLUME_ID_UNUSED,
	VOLUME_ID_UNPROBED,
	VOLUME_ID_OTHER,
	VOLUME_ID_FILESYSTEM,
	VOLUME_ID_RAID,
	VOLUME_ID_DISKLABEL,
	VOLUME_ID_CRYPTO,
};

struct volume_id {
	uint8_t		label_raw[VOLUME_ID_LABEL_SIZE];
	size_t		label_raw_len;
	char		label[VOLUME_ID_LABEL_SIZE+1];
	uint8_t		uuid_raw[VOLUME_ID_UUID_SIZE];
	size_t		uuid_raw_len;
	char		uuid[VOLUME_ID_UUID_SIZE+1];
	enum		volume_id_usage usage_id;
	char		*usage;
	char		*type;
	char		type_version[VOLUME_ID_FORMAT_SIZE];

	int		fd;
	uint8_t		*sbbuf;
	size_t		sbbuf_len;
	uint8_t		*seekbuf;
	uint64_t	seekbuf_off;
	size_t		seekbuf_len;
};

/* utils */
extern int volume_id_utf8_encoded_valid_unichar(const char *str);
extern size_t volume_id_set_unicode16(uint8_t *str, size_t len, const uint8_t *buf, enum endian endianess, size_t count);
extern void volume_id_set_usage(struct volume_id *id, enum volume_id_usage usage_id);
extern void volume_id_set_label_raw(struct volume_id *id, const uint8_t *buf, size_t count);
extern void volume_id_set_label_string(struct volume_id *id, const uint8_t *buf, size_t count);
extern void volume_id_set_label_unicode16(struct volume_id *id, const uint8_t *buf, enum endian endianess, size_t count);
extern void volume_id_set_uuid(struct volume_id *id, const uint8_t *buf, size_t len, enum uuid_format format);
extern uint8_t *volume_id_get_buffer(struct volume_id *id, uint64_t off, size_t len);
extern void volume_id_free_buffer(struct volume_id *id);

/* filesystems */
extern int volume_id_probe_cramfs(struct volume_id *id, uint64_t off, uint64_t size);
extern int volume_id_probe_ext(struct volume_id *id, uint64_t off, uint64_t size);
extern int volume_id_probe_vfat(struct volume_id *id, uint64_t off, uint64_t size);
extern int volume_id_probe_hfs_hfsplus(struct volume_id *id, uint64_t off, uint64_t size);
extern int volume_id_probe_hpfs(struct volume_id *id, uint64_t off, uint64_t size);
extern int volume_id_probe_iso9660(struct volume_id *id, uint64_t off, uint64_t size);
extern int volume_id_probe_jfs(struct volume_id *id, uint64_t off, uint64_t size);
extern int volume_id_probe_minix(struct volume_id *id, uint64_t off, uint64_t size);
extern int volume_id_probe_ntfs(struct volume_id *id, uint64_t off, uint64_t size);
extern int volume_id_probe_ocfs1(struct volume_id *id, uint64_t off, uint64_t size);
extern int volume_id_probe_ocfs2(struct volume_id *id, uint64_t off, uint64_t size);
extern int volume_id_probe_reiserfs(struct volume_id *id, uint64_t off, uint64_t size);
extern int volume_id_probe_romfs(struct volume_id *id, uint64_t off, uint64_t size);
extern int volume_id_probe_sysv(struct volume_id *id, uint64_t off, uint64_t size);
extern int volume_id_probe_udf(struct volume_id *id, uint64_t off, uint64_t size);
extern int volume_id_probe_ufs(struct volume_id *id, uint64_t off, uint64_t size);
extern int volume_id_probe_vxfs(struct volume_id *id, uint64_t off, uint64_t size);
extern int volume_id_probe_xfs(struct volume_id *id, uint64_t off, uint64_t size);
extern int volume_id_probe_squashfs(struct volume_id *id, uint64_t off, uint64_t size);
extern int volume_id_probe_netware(struct volume_id *id, uint64_t off, uint64_t size);
extern int volume_id_probe_gfs(struct volume_id *id, uint64_t off, uint64_t size);
extern int volume_id_probe_gfs2(struct volume_id *id, uint64_t off, uint64_t size);

/* special formats */
extern int volume_id_probe_linux_swap(struct volume_id *id, uint64_t off, uint64_t size);
extern int volume_id_probe_luks(struct volume_id *id, uint64_t off, uint64_t size);

/* raid */
extern int volume_id_probe_linux_raid(struct volume_id *id, uint64_t off, uint64_t size);
extern int volume_id_probe_lvm1(struct volume_id *id, uint64_t off, uint64_t size);
extern int volume_id_probe_lvm2(struct volume_id *id, uint64_t off, uint64_t size);
extern int volume_id_probe_ddf_raid(struct volume_id *id, uint64_t off, uint64_t size);
extern int volume_id_probe_oracleasm(struct volume_id *id, uint64_t off, uint64_t size);

/* bios raid */
extern int volume_id_probe_intel_software_raid(struct volume_id *id, uint64_t off, uint64_t size);
extern int volume_id_probe_highpoint_37x_raid(struct volume_id *id, uint64_t off, uint64_t size);
extern int volume_id_probe_highpoint_45x_raid(struct volume_id *id, uint64_t off, uint64_t size);
extern int volume_id_probe_lsi_mega_raid(struct volume_id *id, uint64_t off, uint64_t size);
extern int volume_id_probe_nvidia_raid(struct volume_id *id, uint64_t off, uint64_t size);
extern int volume_id_probe_promise_fasttrack_raid(struct volume_id *id, uint64_t off, uint64_t size);
extern int volume_id_probe_silicon_medley_raid(struct volume_id *id, uint64_t off, uint64_t size);
extern int volume_id_probe_via_raid(struct volume_id *id, uint64_t off, uint64_t size);
extern int volume_id_probe_adaptec_raid(struct volume_id *id, uint64_t off, uint64_t size);
extern int volume_id_probe_jmicron_raid(struct volume_id *id, uint64_t off, uint64_t size);

#endif
