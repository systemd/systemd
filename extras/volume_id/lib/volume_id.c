/*
 * volume_id - reads volume label and uuid
 *
 * Copyright (C) 2005-2007 Kay Sievers <kay.sievers@vrfy.org>
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

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

struct prober {
	volume_id_probe_fn_t prober;
	const char *name[4];
};

static const struct prober prober_raid[] = {
	{ volume_id_probe_linux_raid, { "linux_raid", } },
	{ volume_id_probe_ddf_raid, { "ddf_raid", } },
	{ volume_id_probe_intel_software_raid, { "isw_raid", } },
	{ volume_id_probe_lsi_mega_raid, { "lsi_mega_raid", } },
	{ volume_id_probe_via_raid, { "via_raid", } },
	{ volume_id_probe_silicon_medley_raid, { "silicon_medley_raid", } },
	{ volume_id_probe_nvidia_raid, { "nvidia_raid", } },
	{ volume_id_probe_promise_fasttrack_raid, { "promise_fasttrack_raid", } },
	{ volume_id_probe_highpoint_45x_raid, { "highpoint_raid", } },
	{ volume_id_probe_adaptec_raid, { "adaptec_raid", } },
	{ volume_id_probe_jmicron_raid, { "jmicron_raid", } },
	{ volume_id_probe_lvm1, { "lvm1", } },
	{ volume_id_probe_lvm2, { "lvm2", } },
	{ volume_id_probe_highpoint_37x_raid, { "highpoint_raid", } },
};

static const struct prober prober_filesystem[] = {
	{ volume_id_probe_vfat, { "vfat", } },
	{ volume_id_probe_linux_swap, { "swap", } },
	{ volume_id_probe_luks, { "luks", } },
	{ volume_id_probe_xfs, { "xfs", } },
	{ volume_id_probe_ext, { "ext2", "ext3", "jbd", } },
	{ volume_id_probe_reiserfs, { "reiserfs", "reiser4", } },
	{ volume_id_probe_jfs, { "jfs", } },
	{ volume_id_probe_udf, { "udf", } },
	{ volume_id_probe_iso9660, { "iso9660", } },
	{ volume_id_probe_hfs_hfsplus, { "hfs", "hfsplus", } },
	{ volume_id_probe_ufs, { "ufs", } },
	{ volume_id_probe_ntfs, { "ntfs", } },
	{ volume_id_probe_cramfs, { "cramfs", } },
	{ volume_id_probe_romfs, { "romfs", } },
	{ volume_id_probe_hpfs, { "hpfs", } },
	{ volume_id_probe_sysv, { "sysv", "xenix", } },
	{ volume_id_probe_minix, { "minix",  } },
	{ volume_id_probe_ocfs1, { "ocfs1", } },
	{ volume_id_probe_ocfs2, { "ocfs2", } },
	{ volume_id_probe_vxfs, { "vxfs", } },
	{ volume_id_probe_squashfs, { "squashfs", } },
	{ volume_id_probe_netware, { "netware", } },
};

/* the user can overwrite this log function */
static void default_log(int priority, const char *file, int line, const char *format, ...)
{
	return;
}

volume_id_log_fn_t volume_id_log_fn = default_log;

/**
 * volume_id_get_label:
 * @type: Type string.
 *
 * Lookup the probing function for a specific type.
 *
 * Returns: The probing function for the given type, #NULL otherwise.
 **/
const volume_id_probe_fn_t *volume_id_get_prober_by_type(const char *type)
{
	unsigned int p, n;

	if (type == NULL)
		return NULL;

	for (p = 0; p < ARRAY_SIZE(prober_raid); p++)
		for (n = 0; prober_raid[p].name[n] !=  NULL; n++)
			if (strcmp(type, prober_raid[p].name[n]) == 0)
				return &prober_raid[p].prober;
	for (p = 0; p < ARRAY_SIZE(prober_filesystem); p++)
		for (n = 0; prober_filesystem[p].name[n] !=  NULL; n++)
			if (strcmp(type, prober_filesystem[p].name[n]) == 0)
				return &prober_filesystem[p].prober;
	return NULL;
}

/**
 * volume_id_get_label:
 * @id: Probing context.
 * @label: Label string. Must not be freed by the caller.
 *
 * Get the label string after a successful probe. Unicode
 * is translated to UTF-8.
 *
 * Returns: 1 if the value was set, 0 otherwise.
 **/
int volume_id_get_label(struct volume_id *id, const char **label)
{
	if (id == NULL)
		return 0;
	if (label == NULL)
		return 0;
	if (id->usage_id == VOLUME_ID_UNUSED)
		return 0;

	*label = id->label;
	return 1;
}

/**
 * volume_id_get_label_raw:
 * @id: Probing context.
 * @label: Label byte array. Must not be freed by the caller.
 * @len: Length of raw label byte array.
 *
 * Get the raw label byte array after a successful probe. It may
 * contain undecoded multibyte character streams.
 *
 * Returns: 1 if the value was set, 0 otherwise.
 **/
int volume_id_get_label_raw(struct volume_id *id, const uint8_t **label, size_t *len)
{
	if (id == NULL)
		return 0;
	if (label == NULL)
		return 0;
	if (len == NULL)
		return 0;
	if (id->usage_id == VOLUME_ID_UNUSED)
		return 0;

	*label = id->label_raw;
	*len = id->label_raw_len;
	return 1;
}

/**
 * volume_id_get_uuid:
 * @id: Probing context.
 * @uuid: UUID string. Must not be freed by the caller.
 *
 * Get the raw UUID string after a successful probe.
 *
 * Returns: 1 if the value was set, 0 otherwise.
 **/
int volume_id_get_uuid(struct volume_id *id, const char **uuid)
{
	if (id == NULL)
		return 0;
	if (uuid == NULL)
		return 0;
	if (id->usage_id == VOLUME_ID_UNUSED)
		return 0;

	*uuid = id->uuid;
	return 1;
}

/**
 * volume_id_get_uuid_raw:
 * @id: Probing context.
 * @uuid: UUID byte array. Must not be freed by the caller.
 * @len: Length of raw UUID byte array.
 *
 * Get the raw UUID byte array after a successful probe. It may
 * contain unconverted endianes values.
 *
 * Returns: 1 if the value was set, 0 otherwise.
 **/
int volume_id_get_uuid_raw(struct volume_id *id, const uint8_t **uuid, size_t *len)
{
	if (id == NULL)
		return 0;
	if (uuid == NULL)
		return 0;
	if (len == NULL)
		return 0;
	if (id->usage_id == VOLUME_ID_UNUSED)
		return 0;

	*uuid = id->uuid_raw;
	*len = id->uuid_raw_len;
	return 1;
}

/**
 * volume_id_get_usage:
 * @id: Probing context.
 * @usage: Usage string. Must not be freed by the caller.
 *
 * Get the usage string after a successful probe.
 *
 * Returns: 1 if the value was set, 0 otherwise.
 **/
int volume_id_get_usage(struct volume_id *id, const char **usage)
{
	if (id == NULL)
		return 0;
	if (usage == NULL)
		return 0;
	if (id->usage_id == VOLUME_ID_UNUSED)
		return 0;

	*usage = id->usage;
	return 1;
}

/**
 * volume_id_get_type:
 * @id: Probing context
 * @type: Type string. Must not be freed by the caller.
 *
 * Get the type string after a successful probe.
 *
 * Returns: 1 if the value was set, 0 otherwise.
 **/
int volume_id_get_type(struct volume_id *id, const char **type)
{
	if (id == NULL)
		return 0;
	if (type == NULL)
		return 0;
	if (id->usage_id == VOLUME_ID_UNUSED)
		return 0;

	*type = id->type;
	return 1;
}

/**
 * volume_id_get_type_version:
 * @id: Probing context.
 * @type_version: Type version string. Must not be freed by the caller.
 *
 * Get the Type version string after a successful probe.
 *
 * Returns: 1 if the value was set, 0 otherwise.
 **/
int volume_id_get_type_version(struct volume_id *id, const char **type_version)
{
	if (id == NULL)
		return 0;
	if (type_version == NULL)
		return 0;
	if (id->usage_id == VOLUME_ID_UNUSED)
		return 0;

	*type_version = id->type_version;
	return 1;
}

static int needs_encoding(const char c)
{
	if ((c >= '0' && c <= '9') ||
	    (c >= 'A' && c <= 'Z') ||
	    (c >= 'a' && c <= 'z') ||
	    strchr(ALLOWED_CHARS, c))
		return 0;
	return 1;
}

/**
 * volume_id_encode_string:
 * @str: Input string to be encoded.
 * @str_enc: Target string to store the encoded input.
 * @len: Location to store the encoded string. The target string,
 * which may be four times as long as the input string.
 *
 * Encode all potentially unsafe characters of a string to the
 * corresponding hex value prefixed by '\x'.
 *
 * Returns: 1 if the entire string was copied, 0 otherwise.
 **/
int volume_id_encode_string(const char *str, char *str_enc, size_t len)
{
	size_t i, j;

	if (str == NULL || str_enc == NULL || len == 0)
		return 0;

	str_enc[0] = '\0';
	for (i = 0, j = 0; str[i] != '\0'; i++) {
		int seqlen;

		seqlen = volume_id_utf8_encoded_valid_unichar(&str[i]);
		if (seqlen > 1) {
			memcpy(&str_enc[j], &str[i], seqlen);
			j += seqlen;
			i += (seqlen-1);
		} else if (str[i] == '\\' || needs_encoding(str[i])) {
			sprintf(&str_enc[j], "\\x%02x", (unsigned char) str[i]);
			j += 4;
		} else {
			str_enc[j] = str[i];
			j++;
		}
		if (j+3 >= len)
			goto err;
	}
	str_enc[j] = '\0';
	return 1;
err:
	return 0;
}

/**
 * volume_id_probe_raid:
 * @id: Probing context.
 * @off: Probing offset relative to the start of the device.
 * @size: Total size of the device.
 *
 * Probe device for all known raid signatures.
 *
 * Returns: 0 on successful probe, otherwise negative value.
 **/
int volume_id_probe_raid(struct volume_id *id, uint64_t off, uint64_t size)
{
	unsigned int i;

	if (id == NULL)
		return -EINVAL;

	info("probing at offset 0x%llx, size 0x%llx",
	    (unsigned long long) off, (unsigned long long) size);

	for (i = 0; i < ARRAY_SIZE(prober_raid); i++)
		if (prober_raid[i].prober(id, off, size) == 0)
			goto found;
	return -1;

found:
	/* If recognized, we free the allocated buffers */
	volume_id_free_buffer(id);
	return 0;
}

/**
 * volume_id_probe_filesystem:
 * @id: Probing context.
 * @off: Probing offset relative to the start of the device.
 * @size: Total size of the device.
 *
 * Probe device for all known filesystem signatures.
 *
 * Returns: 0 on successful probe, otherwise negative value.
 **/
int volume_id_probe_filesystem(struct volume_id *id, uint64_t off, uint64_t size)
{
	unsigned int i;

	if (id == NULL)
		return -EINVAL;

	info("probing at offset 0x%llx, size 0x%llx",
	    (unsigned long long) off, (unsigned long long) size);

	for (i = 0; i < ARRAY_SIZE(prober_filesystem); i++)
		if (prober_filesystem[i].prober(id, off, size) == 0)
			goto found;
	return -1;

found:
	/* If recognized, we free the allocated buffers */
	volume_id_free_buffer(id);
	return 0;
}

/**
 * volume_id_probe_all:
 * @id: Probing context.
 * @off: Probing offset relative to the start of the device.
 * @size: Total size of the device.
 *
 * Probe device for all known raid and filesystem signatures.
 *
 * Returns: 0 on successful probe, otherwise negative value.
 **/
int volume_id_probe_all(struct volume_id *id, uint64_t off, uint64_t size)
{
	if (id == NULL)
		return -EINVAL;

	/* probe for raid first, because fs probes may be successful on raid members */
	if (volume_id_probe_raid(id, off, size) == 0)
		return 0;

	if (volume_id_probe_filesystem(id, off, size) == 0)
		return 0;

	return -1;
}

/**
 * volume_id_probe_raid:
 * @all_probers_fn: prober function to called for all known probing routines.
 * @id: Context passed to prober function.
 * @off: Offset value passed to prober function.
 * @size: Size value passed to prober function.
 * @data: Arbitrary data passed to the prober function.
 *
 * Run a custom function for all known probing routines.
 **/
void volume_id_all_probers(all_probers_fn_t all_probers_fn,
			   struct volume_id *id, uint64_t off, uint64_t size,
			   void *data)
{
	unsigned int i;

	if (all_probers_fn == NULL)
		return;

	for (i = 0; i < ARRAY_SIZE(prober_raid); i++)
		if (all_probers_fn(prober_raid[i].prober, id, off, size, data) != 0)
			goto out;
	for (i = 0; i < ARRAY_SIZE(prober_filesystem); i++)
		if (all_probers_fn(prober_filesystem[i].prober, id, off, size, data) != 0)
			goto out;
out:
	return;
}

/**
 * volume_id_open_fd:
 * @id: Probing context.
 * @fd: Open file descriptor of device to read from.
 *
 * Create the context for probing.
 *
 * Returns: Probing context, or #NULL on failure.
 **/
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

/**
 * volume_id_close:
 * @id: Probing context.
 *
 * Release probing context and free all associated data.
 */
void volume_id_close(struct volume_id *id)
{
	if (id == NULL)
		return;

	if (id->fd_close != 0)
		close(id->fd);

	volume_id_free_buffer(id);

	free(id);
}
