/*
 * volume_id - reads filesystem label and uuid
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
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "volume_id.h"
#include "logging.h"
#include "util.h"

#include "ext.h"
#include "reiserfs.h"
#include "fat.h"
#include "hfs.h"
#include "jfs.h"
#include "xfs.h"
#include "ufs.h"
#include "ntfs.h"
#include "iso9660.h"
#include "udf.h"
#include "highpoint.h"
#include "isw_raid.h"
#include "lsi_raid.h"
#include "via_raid.h"
#include "silicon_raid.h"
#include "nvidia_raid.h"
#include "promise_raid.h"
#include "luks.h"
#include "linux_swap.h"
#include "linux_raid.h"
#include "lvm.h"
#include "cramfs.h"
#include "hpfs.h"
#include "romfs.h"
#include "sysv.h"
#include "minix.h"
#include "mac.h"
#include "msdos.h"
#include "ocfs.h"
#include "vxfs.h"

int volume_id_probe_all(struct volume_id *id, uint64_t off, uint64_t size)
{
	if (id == NULL)
		return -EINVAL;

	/* probe for raid first, cause fs probes may be successful on raid members */
	if (size) {
		if (volume_id_probe_linux_raid(id, off, size) == 0)
			goto exit;

		if (volume_id_probe_intel_software_raid(id, off, size) == 0)
			goto exit;

		if (volume_id_probe_lsi_mega_raid(id, off, size) == 0)
			goto exit;

		if (volume_id_probe_via_raid(id, off, size) == 0)
			goto exit;

		if (volume_id_probe_silicon_medley_raid(id, off, size) == 0)
			goto exit;

		if (volume_id_probe_nvidia_raid(id, off, size) == 0)
			goto exit;

		if (volume_id_probe_promise_fasttrack_raid(id, off, size) == 0)
			goto exit;

		if (volume_id_probe_highpoint_45x_raid(id, off, size) == 0)
			goto exit;
	}

	if (volume_id_probe_lvm1(id, off) == 0)
		goto exit;

	if (volume_id_probe_lvm2(id, off) == 0)
		goto exit;

	if (volume_id_probe_highpoint_37x_raid(id, off) == 0)
		goto exit;

	if (volume_id_probe_luks(id, off) == 0)
		goto exit;

	/* signature in the first block, only small buffer needed */
	if (volume_id_probe_vfat(id, off) == 0)
		goto exit;

	if (volume_id_probe_xfs(id, off) == 0)
		goto exit;

	/* fill buffer with maximum */
	volume_id_get_buffer(id, 0, SB_BUFFER_SIZE);

	if (volume_id_probe_linux_swap(id, off) == 0)
		goto exit;

	if (volume_id_probe_ext(id, off) == 0)
		goto exit;

	if (volume_id_probe_reiserfs(id, off) == 0)
		goto exit;

	if (volume_id_probe_jfs(id, off) == 0)
		goto exit;

	if (volume_id_probe_udf(id, off) == 0)
		goto exit;

	if (volume_id_probe_iso9660(id, off) == 0)
		goto exit;

	if (volume_id_probe_hfs_hfsplus(id, off) == 0)
		goto exit;

	if (volume_id_probe_ufs(id, off) == 0)
		goto exit;

	if (volume_id_probe_ntfs(id, off)  == 0)
		goto exit;

	if (volume_id_probe_cramfs(id, off) == 0)
		goto exit;

	if (volume_id_probe_romfs(id, off) == 0)
		goto exit;

	if (volume_id_probe_hpfs(id, off) == 0)
		goto exit;

	if (volume_id_probe_sysv(id, off) == 0)
		goto exit;

	if (volume_id_probe_minix(id, off) == 0)
		goto exit;

	if (volume_id_probe_ocfs1(id, off) == 0)
		goto exit;

	if (volume_id_probe_ocfs2(id, off) == 0)
		goto exit;

	if (volume_id_probe_vxfs(id, off) == 0)
		goto exit;

	return -1;

exit:
	/* If the filestystem in recognized, we free the allocated buffers,
	   otherwise they will stay in place for the possible next probe call */
	volume_id_free_buffer(id);

	return 0;
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
	char tmp_node[VOLUME_ID_PATH_MAX];

	snprintf(tmp_node, VOLUME_ID_PATH_MAX,
		 "/dev/.volume_id-%u-%u-%u", getpid(), major(devt), minor(devt));
	tmp_node[VOLUME_ID_PATH_MAX-1] = '\0';

	/* create tempory node to open the block device */
	unlink(tmp_node);
	if (mknod(tmp_node, (S_IFBLK | 0600), devt) != 0)
		return NULL;

	id = volume_id_open_node(tmp_node);

	unlink(tmp_node);

	return id;
}

void volume_id_close(struct volume_id *id)
{
	if (id == NULL)
		return;

	if (id->fd_close != 0)
		close(id->fd);

	volume_id_free_buffer(id);

	if (id->partitions != NULL)
		free(id->partitions);

	free(id);
}
