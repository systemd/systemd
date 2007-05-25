/*
 * volume_id - reads filesystem label and uuid
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

/* count of characters used to encode one unicode char */
static int utf8_encoded_expected_len(const char *str)
{
	unsigned char c = (unsigned char)str[0];

	if (c < 0x80)
		return 1;
	if ((c & 0xe0) == 0xc0)
		return 2;
	if ((c & 0xf0) == 0xe0)
		return 3;
	if ((c & 0xf8) == 0xf0)
		return 4;
	if ((c & 0xfc) == 0xf8)
		return 5;
	if ((c & 0xfe) == 0xfc)
		return 6;
	return 0;
}

/* decode one unicode char */
static int utf8_encoded_to_unichar(const char *str)
{
	int unichar;
	int len;
	int i;

	len = utf8_encoded_expected_len(str);
	switch (len) {
	case 1:
		return (int)str[0];
	case 2:
		unichar = str[0] & 0x1f;
		break;
	case 3:
		unichar = (int)str[0] & 0x0f;
		break;
	case 4:
		unichar = (int)str[0] & 0x07;
		break;
	case 5:
		unichar = (int)str[0] & 0x03;
		break;
	case 6:
		unichar = (int)str[0] & 0x01;
		break;
	default:
		return -1;
	}

	for (i = 1; i < len; i++) {
		if (((int)str[i] & 0xc0) != 0x80)
			return -1;
		unichar <<= 6;
		unichar |= (int)str[i] & 0x3f;
	}

	return unichar;
}

/* expected size used to encode one unicode char */
static int utf8_unichar_to_encoded_len(int unichar)
{
	if (unichar < 0x80)
		return 1;
	if (unichar < 0x800)
		return 2;
	if (unichar < 0x10000)
		return 3;
	if (unichar < 0x200000)
		return 4;
	if (unichar < 0x4000000)
		return 5;
	return 6;
}

/* check if unicode char has a valid numeric range */
static int utf8_unichar_valid_range(int unichar)
{
	if (unichar > 0x10ffff)
		return 0;
	if ((unichar & 0xfffff800) == 0xd800)
		return 0;
	if ((unichar > 0xfdcf) && (unichar < 0xfdf0))
		return 0;
	if ((unichar & 0xffff) == 0xffff)
		return 0;
	return 1;
}

/* validate one encoded unicode char and return its length */
int volume_id_utf8_encoded_valid_unichar(const char *str)
{
	int len;
	int unichar;
	int i;

	len = utf8_encoded_expected_len(str);
	if (len == 0)
		return -1;

	/* ascii is valid */
	if (len == 1)
		return 1;

	/* check if expected encoded chars are available */
	for (i = 0; i < len; i++)
		if ((str[i] & 0x80) != 0x80)
			return -1;

	unichar = utf8_encoded_to_unichar(str);

	/* check if encoded length matches encoded value */
	if (utf8_unichar_to_encoded_len(unichar) != len)
		return -1;

	/* check if value has valid range */
	if (!utf8_unichar_valid_range(unichar))
		return -1;

	return len;
}

size_t volume_id_set_unicode16(uint8_t *str, size_t len, const uint8_t *buf, enum endian endianess, size_t count)
{
	size_t i, j;
	uint16_t c;

	j = 0;
	for (i = 0; i + 2 <= count; i += 2) {
		if (endianess == LE)
			c = (buf[i+1] << 8) | buf[i];
		else
			c = (buf[i] << 8) | buf[i+1];
		if (c == 0) {
			str[j] = '\0';
			break;
		} else if (c < 0x80) {
			if (j+1 >= len)
				break;
			str[j++] = (uint8_t) c;
		} else if (c < 0x800) {
			if (j+2 >= len)
				break;
			str[j++] = (uint8_t) (0xc0 | (c >> 6));
			str[j++] = (uint8_t) (0x80 | (c & 0x3f));
		} else {
			if (j+3 >= len)
				break;
			str[j++] = (uint8_t) (0xe0 | (c >> 12));
			str[j++] = (uint8_t) (0x80 | ((c >> 6) & 0x3f));
			str[j++] = (uint8_t) (0x80 | (c & 0x3f));
		}
	}
	str[j] = '\0';
	return j;
}

static char *usage_to_string(enum volume_id_usage usage_id)
{
	switch (usage_id) {
	case VOLUME_ID_FILESYSTEM:
		return "filesystem";
	case VOLUME_ID_OTHER:
		return "other";
	case VOLUME_ID_RAID:
		return "raid";
	case VOLUME_ID_DISKLABEL:
		return "disklabel";
	case VOLUME_ID_CRYPTO:
		return "crypto";
	case VOLUME_ID_UNPROBED:
		return "unprobed";
	case VOLUME_ID_UNUSED:
		return "unused";
	}
	return NULL;
}

void volume_id_set_usage(struct volume_id *id, enum volume_id_usage usage_id)
{
	id->usage_id = usage_id;
	id->usage = usage_to_string(usage_id);
}

void volume_id_set_label_raw(struct volume_id *id, const uint8_t *buf, size_t count)
{
	if (count > sizeof(id->label))
		count = sizeof(id->label);

	memcpy(id->label_raw, buf, count);
	id->label_raw_len = count;
}

void volume_id_set_label_string(struct volume_id *id, const uint8_t *buf, size_t count)
{
	size_t i;

	if (count >= sizeof(id->label))
		count = sizeof(id->label)-1;

	memcpy(id->label, buf, count);
	id->label[count] = '\0';

	/* remove trailing whitespace */
	i = strnlen(id->label, count);
	while (i--) {
		if (!isspace(id->label[i]))
			break;
	}
	id->label[i+1] = '\0';
}

void volume_id_set_label_unicode16(struct volume_id *id, const uint8_t *buf, enum endian endianess, size_t count)
{
	if (count >= sizeof(id->label))
		count = sizeof(id->label)-1;

	 volume_id_set_unicode16((uint8_t *)id->label, sizeof(id->label), buf, endianess, count);
}

void volume_id_set_uuid(struct volume_id *id, const uint8_t *buf, size_t len, enum uuid_format format)
{
	unsigned int i;
	unsigned int count = 0;

	if (len > sizeof(id->uuid_raw))
		len = sizeof(id->uuid_raw);

	switch(format) {
	case UUID_STRING:
		count = len;
		break;
	case UUID_HEX_STRING:
		count = len;
		break;
	case UUID_DOS:
		count = 4;
		break;
	case UUID_64BIT_LE:
	case UUID_64BIT_BE:
		count = 8;
		break;
	case UUID_DCE:
		count = 16;
		break;
	case UUID_FOURINT:
		count = 35;
		break;
	}
	memcpy(id->uuid_raw, buf, count);
	id->uuid_raw_len = count;

	/* if set, create string in the same format, the native platform uses */
	for (i = 0; i < count; i++)
		if (buf[i] != 0)
			goto set;
	return;

set:
	switch(format) {
	case UUID_DOS:
		sprintf(id->uuid, "%02X%02X-%02X%02X",
			buf[3], buf[2], buf[1], buf[0]);
		break;
	case UUID_64BIT_LE:
		sprintf(id->uuid,"%02X%02X%02X%02X%02X%02X%02X%02X",
			buf[7], buf[6], buf[5], buf[4],
			buf[3], buf[2], buf[1], buf[0]);
		break;
	case UUID_64BIT_BE:
		sprintf(id->uuid,"%02X%02X%02X%02X%02X%02X%02X%02X",
			buf[0], buf[1], buf[2], buf[3],
			buf[4], buf[5], buf[6], buf[7]);
		break;
	case UUID_DCE:
		sprintf(id->uuid,
			"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
			buf[0], buf[1], buf[2], buf[3],
			buf[4], buf[5],
			buf[6], buf[7],
			buf[8], buf[9],
			buf[10], buf[11], buf[12], buf[13], buf[14],buf[15]);
		break;
	case UUID_HEX_STRING:
		/* translate A..F to a..f */
		memcpy(id->uuid, buf, count);
		for (i = 0; i < count; i++)
			if (id->uuid[i] >= 'A' && id->uuid[i] <= 'F')
				id->uuid[i] = (id->uuid[i] - 'A') + 'a';
		id->uuid[count] = '\0';
		break;
	case UUID_STRING:
		memcpy(id->uuid, buf, count);
		id->uuid[count] = '\0';
		break;
	case UUID_FOURINT:
		sprintf(id->uuid,
			"%02x%02x%02x%02x:%02x%02x%02x%02x:%02x%02x%02x%02x:%02x%02x%02x%02x",
			buf[0], buf[1], buf[2], buf[3],
			buf[4], buf[5], buf[6], buf[7],
			buf[8], buf[9], buf[10], buf[11],
			buf[12], buf[13], buf[14],buf[15]);
		break;
	}
}

uint8_t *volume_id_get_buffer(struct volume_id *id, uint64_t off, size_t len)
{
	ssize_t buf_len;

	info("get buffer off 0x%llx(%llu), len 0x%zx", (unsigned long long) off, (unsigned long long) off, len);
	/* check if requested area fits in superblock buffer */
	if (off + len <= SB_BUFFER_SIZE) {
		if (id->sbbuf == NULL) {
			id->sbbuf = malloc(SB_BUFFER_SIZE);
			if (id->sbbuf == NULL) {
				dbg("error malloc");
				return NULL;
			}
		}

		/* check if we need to read */
		if ((off + len) > id->sbbuf_len) {
			info("read sbbuf len:0x%llx", (unsigned long long) (off + len));
			if (lseek(id->fd, 0, SEEK_SET) < 0) {
				dbg("lseek failed (%s)", strerror(errno));
				return NULL;
			}
			buf_len = read(id->fd, id->sbbuf, off + len);
			if (buf_len < 0) {
				dbg("read failed (%s)", strerror(errno));
				return NULL;
			}
			dbg("got 0x%zx (%zi) bytes", buf_len, buf_len);
			id->sbbuf_len = buf_len;
			if ((size_t)buf_len < off + len) {
				dbg("requested 0x%zx bytes, got only 0x%zx bytes", len, buf_len);
				return NULL;
			}
		}

		return &(id->sbbuf[off]);
	} else {
		if (len > SEEK_BUFFER_SIZE) {
			dbg("seek buffer too small %d", SEEK_BUFFER_SIZE);
			return NULL;
		}

		/* get seek buffer */
		if (id->seekbuf == NULL) {
			id->seekbuf = malloc(SEEK_BUFFER_SIZE);
			if (id->seekbuf == NULL) {
				dbg("error malloc");
				return NULL;
			}
		}

		/* check if we need to read */
		if ((off < id->seekbuf_off) || ((off + len) > (id->seekbuf_off + id->seekbuf_len))) {
			info("read seekbuf off:0x%llx len:0x%zx", (unsigned long long) off, len);
			if (lseek(id->fd, off, SEEK_SET) < 0) {
				dbg("lseek failed (%s)", strerror(errno));
				return NULL;
			}
			buf_len = read(id->fd, id->seekbuf, len);
			if (buf_len < 0) {
				dbg("read failed (%s)", strerror(errno));
				return NULL;
			}
			dbg("got 0x%zx (%zi) bytes", buf_len, buf_len);
			id->seekbuf_off = off;
			id->seekbuf_len = buf_len;
			if ((size_t)buf_len < len) {
				dbg("requested 0x%zx bytes, got only 0x%zx bytes", len, buf_len);
				return NULL;
			}
		}

		return &(id->seekbuf[off - id->seekbuf_off]);
	}
}

void volume_id_free_buffer(struct volume_id *id)
{
	if (id->sbbuf != NULL) {
		free(id->sbbuf);
		id->sbbuf = NULL;
		id->sbbuf_len = 0;
	}
	if (id->seekbuf != NULL) {
		free(id->seekbuf);
		id->seekbuf = NULL;
		id->seekbuf_len = 0;
	}
}
