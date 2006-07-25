/*
 * volume_id - reads volume label and uuid
 *
 * Copyright (C) 2005 Kay Sievers <kay.sievers@vrfy.org>
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
 */

#ifndef _LIBVOLUME_ID_H_
#define _LIBVOLUME_ID_H_

#include <stdint.h>
#include <stddef.h>

#ifndef PACKED
#define PACKED				__attribute__((packed))
#endif


typedef void (*volume_id_log_fn_t)(int priority, const char *file, int line, const char *format, ...)
	     __attribute__ ((format(printf, 4, 5)));

extern volume_id_log_fn_t volume_id_log_fn;

#define VOLUME_ID_LABEL_SIZE		64
#define VOLUME_ID_UUID_SIZE		36
#define VOLUME_ID_FORMAT_SIZE		32
#define VOLUME_ID_PATH_MAX		256
#define VOLUME_ID_PARTITIONS_MAX	256

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
	int		fd_close:1;
};

extern struct volume_id *volume_id_open_fd(int fd);
extern struct volume_id *volume_id_open_node(const char *path);
extern int volume_id_probe_all(struct volume_id *id, uint64_t off, uint64_t size);
extern int volume_id_probe_filesystem(struct volume_id *id, uint64_t off, uint64_t size);
extern int volume_id_probe_raid(struct volume_id *id, uint64_t off, uint64_t size);
extern void volume_id_close(struct volume_id *id);

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
