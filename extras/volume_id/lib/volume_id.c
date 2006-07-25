/*
 * volume_id - reads volume label and uuid
 *
 * Copyright (C) 2005 Kay Sievers <kay.sievers@vrfy.org>
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
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

#include "libvolume_id.h"
#include "util.h"

/* the user can overwrite this log function */
static void default_log(int priority, const char *file, int line, const char *format, ...)
{
	return;
}

volume_id_log_fn_t volume_id_log_fn = default_log;

int volume_id_probe_raid(struct volume_id *id, uint64_t off, uint64_t size)
{
	if (id == NULL)
		return -EINVAL;

	info("probing at offset 0x%llx, size 0x%llx",
	    (unsigned long long) off, (unsigned long long) size);

	/* probe for raid first, because fs probes may be successful on raid members */
	if (size) {
		if (volume_id_probe_linux_raid(id, off, size) == 0)
			goto found;

		if (volume_id_probe_intel_software_raid(id, off, size) == 0)
			goto found;

		if (volume_id_probe_lsi_mega_raid(id, off, size) == 0)
			goto found;

		if (volume_id_probe_via_raid(id, off, size) == 0)
			goto found;

		if (volume_id_probe_silicon_medley_raid(id, off, size) == 0)
			goto found;

		if (volume_id_probe_nvidia_raid(id, off, size) == 0)
			goto found;

		if (volume_id_probe_promise_fasttrack_raid(id, off, size) == 0)
			goto found;

		if (volume_id_probe_highpoint_45x_raid(id, off, size) == 0)
			goto found;

		if (volume_id_probe_adaptec_raid(id, off, size) == 0)
			goto found;

		if (volume_id_probe_jmicron_raid(id, off, size) == 0)
			goto found;
	}

	if (volume_id_probe_lvm1(id, off, size) == 0)
		goto found;

	if (volume_id_probe_lvm2(id, off, size) == 0)
		goto found;

	if (volume_id_probe_highpoint_37x_raid(id, off, size) == 0)
		goto found;

	return -1;

found:
	/* If recognized, we free the allocated buffers */
	volume_id_free_buffer(id);
	return 0;
}

int volume_id_probe_filesystem(struct volume_id *id, uint64_t off, uint64_t size)
{
	if (id == NULL)
		return -EINVAL;

	info("probing at offset 0x%llx, size 0x%llx",
	    (unsigned long long) off, (unsigned long long) size);

	if (volume_id_probe_vfat(id, off, size) == 0)
		goto found;

	/* fill buffer with maximum */
	volume_id_get_buffer(id, 0, SB_BUFFER_SIZE);

	if (volume_id_probe_linux_swap(id, off, size) == 0)
		goto found;

	if (volume_id_probe_luks(id, off, size) == 0)
		goto found;

	if (volume_id_probe_xfs(id, off, size) == 0)
		goto found;

	if (volume_id_probe_ext(id, off, size) == 0)
		goto found;

	if (volume_id_probe_reiserfs(id, off, size) == 0)
		goto found;

	if (volume_id_probe_jfs(id, off, size) == 0)
		goto found;

	if (volume_id_probe_udf(id, off, size) == 0)
		goto found;

	if (volume_id_probe_iso9660(id, off, size) == 0)
		goto found;

	if (volume_id_probe_hfs_hfsplus(id, off, size) == 0)
		goto found;

	if (volume_id_probe_ufs(id, off, size) == 0)
		goto found;

	if (volume_id_probe_ntfs(id, off, size)  == 0)
		goto found;

	if (volume_id_probe_cramfs(id, off, size) == 0)
		goto found;

	if (volume_id_probe_romfs(id, off, size) == 0)
		goto found;

	if (volume_id_probe_hpfs(id, off, size) == 0)
		goto found;

	if (volume_id_probe_sysv(id, off, size) == 0)
		goto found;

	if (volume_id_probe_minix(id, off, size) == 0)
		goto found;

	if (volume_id_probe_ocfs1(id, off, size) == 0)
		goto found;

	if (volume_id_probe_ocfs2(id, off, size) == 0)
		goto found;

	if (volume_id_probe_vxfs(id, off, size) == 0)
		goto found;

	if (volume_id_probe_squashfs(id, off, size) == 0)
		goto found;

	if (volume_id_probe_netware(id, off, size) == 0)
		goto found;

	if (volume_id_probe_gfs(id, off, size) == 0)
		goto found;

	if (volume_id_probe_gfs2(id, off, size) == 0)
		goto found;

	return -1;

found:
	/* If recognized, we free the allocated buffers */
	volume_id_free_buffer(id);
	return 0;
}

int volume_id_probe_all(struct volume_id *id, uint64_t off, uint64_t size)
{
	if (id == NULL)
		return -EINVAL;

	if (volume_id_probe_raid(id, off, size) == 0)
		return 0;

	if (volume_id_probe_filesystem(id, off, size) == 0)
		return 0;

	return -1;
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

void volume_id_close(struct volume_id *id)
{
	if (id == NULL)
		return;

	if (id->fd_close != 0)
		close(id->fd);

	volume_id_free_buffer(id);

	free(id);
}
